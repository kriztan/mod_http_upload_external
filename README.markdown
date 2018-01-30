---
description: HTTP File Upload (external service)
labels: 'Stage-Alpha'
---

Introduction
============

This module implements [XEP-0363], which lets clients upload files
over HTTP to an external web server.

This module generates URLs that are signed using a HMAC. Any web service that can authenticate
these URLs can be used. 

Implementations
---------------

* [PHP implementation](https://hg.prosody.im/prosody-modules/raw-file/tip/mod_http_upload_external/share.php)
* [Python3+Flask implementation](https://github.com/horazont/xmpp-http-upload)

To implement your own service compatible with this module, check out the implementation notes below 
(and if you publish your implementation - let us know!).

Configuration
=============

Add `"http_upload_external"` to modules_enabled in your global section, or under the host(s) you wish
to use it on.

External URL
------------

You need to provide the path to the external service. Ensure it ends with '/'.

For example, to use the PHP implementation linked above, you might set it to:

``` {.lua}
http_upload_external_base_url = "https://your.example.com/path/to/share.php/"
```

Secret
------

Set a long and unpredictable string as your secret. This is so the upload service can verify that
the upload comes from mod_http_upload_external, and random strangers can't upload to your server.

``` {.lua}
http_upload_external_secret = "this is a secret string!"
```

You need to set exactly the same secret string in your external service.

Limits
------

A maximum file size can be set by:

``` {.lua}
http_upload_external_file_size_limit = 123 -- bytes
```

Default is 100MB (100\*1024\*1024).

Compatibility
=============

Works with Prosody 0.9.x and later.

Implementation
==============

To implement your own external service that is compatible with this module, you need to expose a
simple API that allows the HTTP GET, HEAD and PUT methods on arbitrary URLs located on your service.

For example, if http_upload_external_base_url is set to `https://example.com/upload/` then your service
might receive the following requests:

Upload a new file:

```
PUT https://example.com/upload/foo/bar.jpg?v=49e9309ff543ace93d25be90635ba8e9965c4f23fc885b2d86c947a5d59e55b2
```

Recipient checks the file size and other headers:

```
HEAD https://example.com/upload/foo/bar.jpg
```

Recipient downloads the file:

```
GET https://example.com/upload/foo/bar.jpg
```

The only tricky logic is in validation of the PUT request. Firstly, don't overwrite existing files (return 409 Conflict).

Then you need to validate the auth token. This will be in the URL query parameter 'v'. If it is absent, fail with 403 Forbidden.

Calculate the expected auth token by reading the value of the Content-Length header of the PUT request. E.g. for a 1MB file
will have a Content-Length of '1048576'. Append this to the uploaded file name, separated by a space (0x20) character.

For the above example, you would end up with the following string: "foo/bar.jpg 1048576"

The auth token is a SHA256 HMAC of this string, using the configured secret as the key. E.g.

```
calculated_auth_token = hmac_sha256("foo/bar.jpg 1048576", "secret string")
```

If this is not equal to the 'v' parameter provided in the upload URL, reject the upload with 403 Forbidden.

Note: your language/environment may provide a function for doing a constant-time comparison of these, to guard against
timing attacks that may be used to discover the secret key.
