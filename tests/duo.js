var Duo = require('../index');

var IKEY = "DIXXXXXXXXXXXXXXXXXX",
    SKEY = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    AKEY = "useacustomerprovidedapplicationsecretkey",
    USER = "testuser",
    INVALID_RESPONSE = "AUTH|INVALID|SIG",
    EXPIRED_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702",
    FUTURE_RESPONSE = "AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef";

module.exports['Signing Checks'] = {
    'sign request with ikey/skey/akey and user': function (test) {
        var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER);
        test.notEqual(request_sig, null, 'Invalid Request');
        test.done();
    },
    'sign request without a user': function (test) {
        var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, "");
        test.equal(request_sig, Duo.ERR_USER, 'Sign request user check failed');
        test.done();
    },
    'sign request with an invalid ikey': function(test) {
        var request_sig = Duo.sign_request("invalid", SKEY, AKEY, USER);
        test.equal(request_sig, Duo.ERR_IKEY, 'Sign request ikey check failed');
        test.done();
    },
    'sign request with an invalid skey': function(test) {
        var request_sig = Duo.sign_request(IKEY, "invalid", AKEY, USER);
        test.equal(request_sig, Duo.ERR_SKEY, 'Sign request skey check failed');
        test.done();
    },
    'sign request with an invalid akey': function(test) {
        var request_sig = Duo.sign_request(IKEY, SKEY, "invalid", USER);
        test.equal(request_sig, Duo.ERR_AKEY, 'Sign request akey check failed');
        test.done();
    },
};

request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER);
var parts = request_sig.split(':');
var duo_sig = parts[0];
var valid_app_sig = parts[1];

request_sig = Duo.sign_request(IKEY, SKEY, "invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid", USER);
parts = request_sig.split(':');
var invalid_app_sig = parts[1];

module.exports['Verify Checks'] = {
    'verify request': function(test) {
        var user = Duo.verify_response(IKEY, SKEY, AKEY, INVALID_RESPONSE + ":" + valid_app_sig);
        test.equal(user, null, 'Invalid response check failed');
        test.done();
    },
    'expire check': function (test) {
        var user = Duo.verify_response(IKEY, SKEY, AKEY, EXPIRED_RESPONSE + ":" + valid_app_sig);
        test.equal(user, null, 'Expired response check failed');
        test.done();
    },
    'invalid app sig': function (test) {
        var user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + invalid_app_sig);
        test.equal(user, null, 'Invalid app sig check failed');
        test.done();
    },
    'verify response on valid signature': function (test) {
        user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ":" + valid_app_sig);
        test.equal(user, USER, 'verify response failed on valid signature');
        test.done();
    }
};