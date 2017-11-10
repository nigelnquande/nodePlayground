// Simple Hello World server
const zlib = require('zlib');
const http = require("http");
const fs = require("fs");
const url = require("url");
const path = require("path");
const auth = require("basic-auth");
const _ = require("lodash");
const session = require("cookie-session"); // store sessions in cookies
const express = require("express");
const aes = require("aes-js"); // used for encrypting/decrypting user passwords as needed
const crypt = require("crypto");
const accepts = require("accepts");

var app = express();

app.use(session({
  name: 'session',
  keys: [/* secret keys */],
 
  // Cookie Options
  maxAge: 24 * 60 * 60 * 7 * 1000 // 1 week
}));

// files to be served
const favicon = path.join(__dirname, 'favicon.ico');
const aes_js = path.join(__dirname, 'js', 'aes.min.js');

/* If the browser can accept Gzip or deflate compression, send it compressed output. Otherwise, send it the stream's contents. */
var sendResponse = function (file, request, response, stat) {
	if (_.isUndefined(stat)) stat = 200;
	var acc = accepts(request);
	const in_stream = fs.createReadStream(file);
	if (acc.encodings().includes("gzip")) {
		try {
			response.writeHead(stat, { 'Content-Encoding': 'gzip' });
			in_stream.pipe(zlib.createGzip()).pipe(response);
			in_stream.pipe(zlib.createGzip()).pipe(response);
		} catch (err) {
			in_stream.pipe(response);
		}
	} else if (acc.encodings().includes("deflate")) {
		try {
			response.writeHead(stat, { 'Content-Encoding': 'deflate' });
			in_stream.pipe(zlib.createDeflate()).pipe(response);
		} catch (err) {
			in_stream.pipe(response);
		}
	} else {
		in_stream.pipe(response);
	}
};

/* Digest authentication logic, adapted from http://www.dotnetcurry.com/nodejs/1237/digest-authentication-nodejs-application 
 * @todo: When the user supplies credentials, get the encrypted password with the matching username from the DB, decrypt it and store it in credentials.
*/

/* Store the valid credentials for the user, to be retrieved from the users DB and decrypted.
 * Credentials must be en/decrypted as the hash **needs** access to the original password text. 
 * Using encryption is definitely not the best way to store passwords (because it is reversible, 
 * which we need here); hashing is better.
 */
var credentials = { 
	userName: 'administrator',
	password: 'Your Super Secret Password Here',
	realm: 'Digest Authentication'
};

var cryptoUsingMD5 = function (data) { return crypt.createHash('md5').update(data).digest('hex') };

var authenticateUser = function (req, res, hash) {
	var rnd = Math.random();
	/* 
	console.log({ 
		'WWW-Authenticate': 'Digest realm="' + credentials.realm + '",qop="auth",nonce="' + rnd + '",opaque="' + hash + '"' 
	});
	*/
	res.setHeader('WWW-Authenticate', 'Digest realm="' + credentials.realm + '",qop="auth",nonce="' + rnd + '",opaque="' + hash + '"');
	sendResponse('unauthenticated.txt', req, res, 401);
};

var parseAuthenticationInfo = function (auth_data) {
	var authentication_obj = {};
	auth_data.split(', ').forEach(function (d) {
		d = d.split('='); authentication_obj[d[0]] = d[1].replace(/"/g, ''); 
	});
	// console.log(JSON.stringify(authenticationObj));
	return authentication_obj;
};

/** Determine if the user has authenticated. */
var userHasAuthenticated = function (req, resp) {
	var authenticated = false;
	var hash = cryptoUsingMD5(credentials.realm);
	var auth_info, digest_auth_obj = {};

	if (!_.isUndefined(req.headers.authorization)) { // has auth headers?
		auth_info = parseAuthenticationInfo(req.headers.authorization.replace(/^Digest /, ''));
		if (auth_info.username === credentials.userName) { // user names match. Check hashed password
			digest_auth_obj.ha1 = cryptoUsingMD5(auth_info.username + ':' + credentials.realm + ':' + credentials.password);
			digest_auth_obj.ha2 = cryptoUsingMD5(req.method + ':' + auth_info.uri);
			digest_auth_obj.response = cryptoUsingMD5(
				[digest_auth_obj.ha1, auth_info.nonce, auth_info.nc, auth_info.cnonce, auth_info.qop, digest_auth_obj.ha2].join(':')
			);
			if (auth_info.response !== digest_auth_obj.response) { authenticateUser(resp); return authenticated; }
			else authenticated = true; // username and password match
		} else {
			console.error("Authentication failure. Try again."); 
			authenticateUser(req, resp, hash); 
			return authenticated; 
		}
	} else { authenticateUser(req, resp, hash); return authenticated; }

	return authenticated;
};

/** Shut down the server if user provides valid authentication details */
var shutdownServer = function (req, resp) {
	console.log("Shutdown requested.");
	if (userHasAuthenticated(req, resp)) {
		server.close(); 
		console.log("Authentication succeeded. Server is now shutting down ..."); 
		sendResponse('shutdown.txt', req, resp, 200); /* serve shutdown message */
	}
	else { 
		console.warn("Authentication failed. Server will not shut down ...");
		sendResponse('unauthenticated.txt', req, resp, 200); /* serve shutdown message */
	}
};

var server = http.createServer(); // create a server instance and run it
server.on('request', function(req, resp) {
	console.log("Request URL:\t%s", req.url);

	if (req.url.match(/^\/poweroff.*/) || req.url.match(/^\/shutdown.*/)) {
		shutdownServer(req, resp);  // use this path to shut down the server, if user has provided proper auth
	} else if (req.url.match(/^\/favicon.*/)) { // output the favicon
		try {
			resp.setHeader('Content-Disposition', "inline; filename=favicon.ico"); // do not download
			resp.setHeader('Content-type', 'image/x-icon'); // output HTTP headings
		} catch (err) {}
		sendResponse(favicon, req, resp, 200);
	} else if (req.url.match(/^\/aes.min.js/)) { // output the JS
		try {
			resp.writeHead(200, {'content-type': 'application/javascript'}); // output HTTP headings
		} catch (err) { }
		sendResponse(aes_js, req, resp, 200);
	} else {
		try {
			resp.writeHead(200, {'content-type': 'application/xhtml+xml; charset=utf-8'}); // output HTTP headings
		} catch (err) {}
		sendResponse('hello.html', req, resp);
	}
});

const port = 8069; // could be read from a config file
server.listen(port); // bind to port

//Set the idle timeout on any new connection
server.once('listening', function () { console.log("Hello server listening on port %d ...", port); });
