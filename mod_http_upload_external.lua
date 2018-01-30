-- mod_http_upload_external
--
-- Copyright (C) 2015-2016 Kim Alvefur
--
-- This file is MIT/X11 licensed.
--

-- imports
local st = require"util.stanza";
local uuid = require"util.uuid".generate;
local http = require "util.http";
local dataform = require "util.dataforms".new;
local HMAC = require "util.hashes".hmac_sha256;

-- config
local file_size_limit = module:get_option_number(module.name .. "_file_size_limit", 100 * 1024 * 1024); -- 100 MB
local base_url = assert(module:get_option_string(module.name .. "_base_url"), module.name .. "_base_url is a required option");
local secret = assert(module:get_option_string(module.name .. "_secret"), module.name .. "_secret is a required option");

-- depends
module:depends("disco");

-- namespace
local xmlns_http_upload = "urn:xmpp:http:upload";

-- identity and feature advertising
module:add_identity("store", "file", module:get_option_string("name", "HTTP File Upload"))
module:add_feature(xmlns_http_upload);

module:add_extension(dataform {
	{ name = "FORM_TYPE", type = "hidden", value = xmlns_http_upload },
	{ name = "max-file-size", type = "text-single" },
}:form({ ["max-file-size"] = tostring(file_size_limit) }, "result"));

local function magic_crypto_dust(random, filename, filesize)
	local message = string.format("%s/%s %d", random, filename, filesize);
	local digest = HMAC(secret, message, true);
	random, filename = http.urlencode(random), http.urlencode(filename);
	return base_url .. random .. "/" .. filename, "?v=" .. digest;
end

-- hooks
module:hook("iq/host/"..xmlns_http_upload..":request", function (event)
	local stanza, origin = event.stanza, event.origin;
	local request = stanza.tags[1];
	-- local clients only
	if origin.type ~= "c2s" then
		module:log("debug", "Request for upload slot from a %s", origin.type);
		origin.send(st.error_reply(stanza, "cancel", "not-authorized"));
		return true;
	end
	-- validate
	local filename = request:get_child_text("filename");
	if not filename or filename:find("/") then
		module:log("debug", "Filename %q not allowed", filename or "");
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Invalid filename"));
		return true;
	end
	local filesize = tonumber(request:get_child_text("size"));
	if not filesize then
		module:log("debug", "Missing file size");
		origin.send(st.error_reply(stanza, "modify", "bad-request", "Missing or invalid file size"));
		return true;
	elseif filesize > file_size_limit then
		module:log("debug", "File too large (%d > %d)", filesize, file_size_limit);
		origin.send(st.error_reply(stanza, "modify", "not-acceptable", "File too large",
			st.stanza("file-too-large", {xmlns=xmlns_http_upload})
				:tag("max-size"):text(tostring(file_size_limit))));
		return true;
	end
	local reply = st.reply(stanza);
	reply:tag("slot", { xmlns = xmlns_http_upload });
	local random = uuid();
	local get_url, verify = magic_crypto_dust(random, filename, filesize);
	reply:tag("get"):text(get_url):up();
	reply:tag("put"):text(get_url .. verify):up();
	module:log("info", "Handed out upload slot %s to %s@%s", get_url, origin.username, origin.host);
	origin.send(reply);
	return true;
end);
