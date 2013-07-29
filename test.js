var Duo = require('./index');

var IKEY = "DIXXXXXXXXXXXXXXXXXX";
var SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
var AKEY = "useacustomerprovidedapplicationsecretkey";

var USER = "testuser";

var INVALID_RESPONSE = "AUTH|INVALID|SIG";
var EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702";
var FUTURE_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef";

/**************************************************************/

var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER);
if (request_sig == null) {
    console.log("Sign request failed.");
}

request_sig = Duo.sign_request(IKEY, SKEY, AKEY, "");
if (request_sig != Duo.ERR_USER) {
    console.log("Sign request user check failed.");
}

request_sig = Duo.sign_request("invalid", SKEY, AKEY, USER);
if (request_sig != Duo.ERR_IKEY) {
    console.log("Sign request ikey check failed.");
}

request_sig = Duo.sign_request(IKEY, "invalid", AKEY, USER);
if (request_sig != Duo.ERR_SKEY) {
    console.log("Sign request skey check failed.");
}

request_sig = Duo.sign_request(IKEY, SKEY, "invalid", USER);
if (request_sig != Duo.ERR_AKEY) {
    console.log("Sign request akey check failed.");
}

/*************************************************************/

request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER);
var parts = request_sig.split(':');
var duo_sig = parts[0];
var valid_app_sig = parts[1];

request_sig = Duo.sign_request(IKEY, SKEY, "invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid", USER);
parts = request_sig.split(':');
var invalid_app_sig = parts[1];

var user = Duo.verify_response(IKEY, SKEY, AKEY, INVALID_RESPONSE + ":" + valid_app_sig);
if (user != null) {
    console.log("invalid response check failed")
}

user = Duo.verify_response(IKEY, SKEY, AKEY, EXPIRED_RESPONSE + ":" + valid_app_sig);
if (user != null) {
    console.log("expired response check failed");
}

user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + invalid_app_sig);
if (user != null) {
    console.log("invalid app sig check failed");
}

user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + valid_app_sig);
if (user != USER) {
    console.log("verify response failed on valid signature");
}

console.log("Tests complete.");
