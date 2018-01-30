<?php

/*
  PHP script to handle file uploads and downloads for Prosody's mod_http_upload_external

  Tested with Apache 2.2+ and PHP 5.3+

  ** Why this script?

  This script only allows uploads that have been authorized by mod_http_upload_external. It
  attempts to make the upload/download as safe as possible, considering that there are *many*
  security concerns involved with allowing arbitrary file upload/download on a web server.

  With that said, I do not consider myself a PHP developer, and at the time of writing, this
  code has had no external review. Use it at your own risk. I make no claims that this code
  is secure.

  ** How to use?

  Drop this file somewhere it will be served by your web server. Edit the config options below.

  In Prosody set:

    http_upload_external_base_url = "https://your.example.com/path/to/share.php/"
    http_upload_external_secret = "this is your secret string"

  ** License

  (C) 2016 Matthew Wild <mwild1@gmail.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy of this software
  and associated documentation files (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all copies or substantial
  portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
  BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
/*         CONFIGURATION OPTIONS                   */
/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

/* Change this to a directory that is writable by your web server, but is outside your web root */
$CONFIG_STORE_DIR = '/tmp';

/* This must be the same as 'http_upload_external_secret' that you set in Prosody's config file */
$CONFIG_SECRET = 'this is your secret string';

/* For people who need options to tweak that they don't understand... here you are */
$CONFIG_CHUNK_SIZE = 4096;

/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/
/*         END OF CONFIGURATION                    */
/*\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\*/

/* Do not edit below this line unless you know what you are doing (spoiler: nobody does) */

$upload_file_name = substr($_SERVER['PHP_SELF'], strlen($_SERVER['SCRIPT_NAME'])+1);
$store_file_name = $CONFIG_STORE_DIR . '/store-' . hash('sha256', $upload_file_name);

$request_method = $_SERVER['REQUEST_METHOD'];

//cors support for all supported methods
if(in_array($request_method, array('OPTIONS', 'HEAD', 'GET', 'PUT')))
{
	header("Access-Control-Allow-Origin: *");
	header("Access-Control-Allow-Headers: Content-Type");
	header("Access-Control-Allow-Methods: OPTIONS, HEAD, GET, PUT");
}

if(array_key_exists('v', $_GET) === TRUE && $request_method === 'PUT') {
	$headers = getallheaders();

	$upload_file_size = $headers['Content-Length'];
	$upload_token = $_GET['v'];

	$calculated_token = hash_hmac('sha256', "$upload_file_name $upload_file_size", $CONFIG_SECRET);
	if($upload_token !== $calculated_token) {
		http_response_code(403);		//Forbidden
		exit;
	}

	/* Check if file already exists */
	if(file_exists($store_file_name)) {
		http_response_code(409);		//Conflict
		exit;
	}

	/* Write file and check if everything could be saved */
	$written=@file_put_contents($store_file_name, fopen('php://input', 'r'));
	if($written!=$_SERVER['CONTENT_LENGTH']) {
		http_response_code(507);		//Insufficient Storage
		exit;
	}

} else if($request_method === 'GET' || $request_method === 'HEAD') {
	// Send file (using X-Sendfile would be nice here...)

	if(file_exists($store_file_name)) {
		$finfo=finfo_open(FILEINFO_MIME_TYPE);
		$mime_type=finfo_file($finfo, $store_file_name);
		finfo_close($finfo);
		header('X-Content-Type-Options: nosniff');		//gives better security in browsers
		header("Content-Type: $mime_type");
		header('Content-Disposition: attachment');
		header('Content-Length: '.filesize($store_file_name));
		if($request_method !== 'HEAD') {
			set_time_limit(0);
			$file = @fopen($store_file_name,"rb");
			while(!feof($file))	{
				print(@fread($file, 1024*8));
				ob_flush();
				flush();
			}
		}
	} else {
		http_response_code(404);		//Not Found
	}
} else if($request_method === 'OPTIONS') {
	;		//do nothing special here
} else {

	http_response_code(400);		//Bad Request
}

exit;

// For 4.3.0 <= PHP <= 5.4.0
// See https://stackoverflow.com/a/12018482/3528174
if (!function_exists('http_response_code'))
{
	function http_response_code($newcode = NULL)
	{
		static $code = 200;
		if($newcode !== NULL)
		{
			header('X-PHP-Response-Code: '.$newcode, true, $newcode);
			if(!headers_sent())
			$code = $newcode;
		}
		return $code;
	}
}