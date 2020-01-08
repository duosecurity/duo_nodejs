/* global describe it */
var Duo = require('../index')
var assert = require('assert')

var IKEY = 'DIXXXXXXXXXXXXXXXXXX'
var WRONG_IKEY = 'DIXXXXXXXXXXXXXXXXXY'
var SKEY = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
var AKEY = 'useacustomerprovidedapplicationsecretkey'
var USER = 'testuser'
var INVALID_RESPONSE = 'AUTH|INVALID|SIG'
var EXPIRED_RESPONSE = 'AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTMwMDE1Nzg3NA==|cb8f4d60ec7c261394cd5ee5a17e46ca7440d702'
var FUTURE_RESPONSE = 'AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0Mw==|d20ad0d1e62d84b00a3e74ec201a5917e77b6aef'
var WRONG_PARAMS_RESPONSE = 'AUTH|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|6cdbec0fbfa0d3f335c76b0786a4a18eac6cdca7'
var WRONG_PARAMS_APP = 'APP|dGVzdHVzZXJ8RElYWFhYWFhYWFhYWFhYWFhYWFh8MTYxNTcyNzI0M3xpbnZhbGlkZXh0cmFkYXRh|7c2065ea122d028b03ef0295a4b4c5521823b9b5'

describe('Signing Checks', function () {
  it('sign request with ikey/skey/akey and user', function (done) {
    var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER)
    assert.notEqual(request_sig, null, 'Invalid Request')
    done()
  })

  it('sign request without a user', function (done) {
    var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, '')
    assert.equal(request_sig, Duo.ERR_USER, 'Sign request user check failed')
    done()
  })

  it('sign request with invalid user', function (done) {
    var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, 'in|valid')
    assert.equal(request_sig, Duo.ERR_USER, 'Sign request user check failed')
    done()
  })

  it('sign request with an invalid ikey', function (done) {
    var request_sig = Duo.sign_request('invalid', SKEY, AKEY, USER)
    assert.equal(request_sig, Duo.ERR_IKEY, 'Sign request ikey check failed')
    done()
  })

  it('sign request with an invalid skey', function (done) {
    var request_sig = Duo.sign_request(IKEY, 'invalid', AKEY, USER)
    assert.equal(request_sig, Duo.ERR_SKEY, 'Sign request skey check failed')
    done()
  })

  it('sign request with an invalid akey', function (done) {
    var request_sig = Duo.sign_request(IKEY, SKEY, 'invalid', USER)
    assert.equal(request_sig, Duo.ERR_AKEY, 'Sign request akey check failed')
    done()
  })
})

var request_sig = Duo.sign_request(IKEY, SKEY, AKEY, USER)
var parts = request_sig.split(':')
var valid_app_sig = parts[1]

request_sig = Duo.sign_request(IKEY, SKEY, 'invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalid', USER)
parts = request_sig.split(':')
var invalid_app_sig = parts[1]

describe('Verify Checks', function () {
  it('verify request', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, INVALID_RESPONSE + ':' + valid_app_sig)
    assert.equal(user, null, 'Invalid response check failed')
    done()
  })
  it('expire check', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, EXPIRED_RESPONSE + ':' + valid_app_sig)
    assert.equal(user, null, 'Expired response check failed')
    done()
  })
  it('invalid app sig', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ':' + invalid_app_sig)
    assert.equal(user, null, 'Invalid app sig check failed')
    done()
  })
  it('verify response on valid signature', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ':' + valid_app_sig)
    assert.equal(user, USER, 'verify response failed on valid signature')
    done()
  })
  it('invalid response format', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, WRONG_PARAMS_RESPONSE + ':' + valid_app_sig)
    assert.equal(user, null, 'Invalid response format check failed')
    done()
  })
  it('invalid app sig format', function (done) {
    var user = Duo.verify_response(IKEY, SKEY, AKEY, FUTURE_RESPONSE + ':' + WRONG_PARAMS_APP)
    assert.equal(user, null, 'Invalid app sig format check failed')
    done()
  })
  it('wrong ikey', function (done) {
    var user = Duo.verify_response(WRONG_IKEY, SKEY, AKEY, FUTURE_RESPONSE + ':' + valid_app_sig)
    assert.equal(user, null, 'Wrong IKEY check failed')
    done()
  })
})
