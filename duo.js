var crypto = require('crypto')

var DUO_PREFIX = 'TX'
var APP_PREFIX = 'APP'
var AUTH_PREFIX = 'AUTH'

var DUO_EXPIRE = 300
var APP_EXPIRE = 3600
var IKEY_LEN = 20
var SKEY_LEN = 40
var AKEY_LEN = 40

/* Exception Messages */
var ERR_USER = 'ERR|The username passed to sign_request() is invalid.'
var ERR_IKEY = 'ERR|The Duo integration key passed to sign_request() is invalid'
var ERR_SKEY = 'ERR|The Duo secret key passed to sign_request() is invalid'
var ERR_AKEY = 'ERR|The application secret key passed to sign_request() must be at least ' + String(AKEY_LEN) + ' characters.'

class UsernameError extends Error {
  constructor (message) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace(this, this.constructor)
  }
}

class IkeyError extends Error {
  constructor (message) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace(this, this.constructor)
  }
}

class AkeyError extends Error {
  constructor (message) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace(this, this.constructor)
  }
}

/**
 * @function sign a value
 *
 * @param {String} key Integration's Secret Key
 * @param {String} vals Value(s) to sign
 * @param {String} prefix DUO/APP/AUTH Prefix
 * @param {Integer} expire time till expiry
 *
 * @return {String} Containing the signed value in sha1-hmac with prefix
 *
 * @api private
 */
function _sign_vals (key, vals, prefix, expire) {
  var exp = Math.round((new Date()).getTime() / 1000) + expire

  var val = vals + '|' + exp

  var b64 = Buffer.from(val).toString('base64')
  var cookie = prefix + '|' + b64

  var sig = crypto.createHmac('sha1', key)
    .update(cookie)
    .digest('hex')

  return cookie + '|' + sig
}

/**
 * @function parses a value
 *
 * @param {String} key Integration's Secret Key
 * @param {String} val Value to unpack
 * @param {String} prefix DUO/APP/AUTH Prefix
 * @param {String} ikey Integration Key
 *
 * @return {String/Null} Returns a username on successful parse. Null if not
 *
 * @api private
 */
function _parse_vals (key, val, prefix, ikey) {
  var ts = Math.round((new Date()).getTime() / 1000)
  var parts = val.split('|')
  if (parts.length !== 3) {
    return null
  }

  var u_prefix = parts[0]
  var u_b64 = parts[1]
  var u_sig = parts[2]

  var sig = crypto.createHmac('sha1', key)
    .update(u_prefix + '|' + u_b64)
    .digest('hex')

  if (crypto.createHmac('sha1', key).update(sig).digest('hex') !== crypto.createHmac('sha1', key).update(u_sig).digest('hex')) {
    return null
  }

  if (u_prefix !== prefix) {
    return null
  }

  var cookie_parts = Buffer.from(u_b64, 'base64').toString('utf8').split('|')
  if (cookie_parts.length !== 3) {
    return null
  }

  var user = cookie_parts[0]
  var u_ikey = cookie_parts[1]
  var exp = cookie_parts[2]

  if (u_ikey !== ikey) {
    return null
  }

  if (ts >= parseInt(exp)) {
    return null
  }

  return user
}

/**
 * @function sign's a login request to be passed onto Duo Security
 *
 * @param {String} ikey Integration Key
 * @param {String} skey Secret Key
 * @param {String} akey Application Security Key
 * @param {String} username Username
 *
 * @return {String} Duo Signature
 *
 * @api public
 */
var sign_request = function (ikey, skey, akey, username) {
  if (!username || username.length < 1) {
    return ERR_USER
  }
  if (username.indexOf('|') !== -1) {
    return ERR_USER
  }
  if (!ikey || ikey.length !== IKEY_LEN) {
    return ERR_IKEY
  }
  if (!skey || skey.length !== SKEY_LEN) {
    return ERR_SKEY
  }
  if (!akey || akey.length < AKEY_LEN) {
    return ERR_AKEY
  }

  var vals = username + '|' + ikey

  var duo_sig = _sign_vals(skey, vals, DUO_PREFIX, DUO_EXPIRE)
  var app_sig = _sign_vals(akey, vals, APP_PREFIX, APP_EXPIRE)

  var sig_request = duo_sig + ':' + app_sig
  return sig_request
}

/**
 * @function verifies a response from Duo Security
 *
 * @param {String} ikey Integration Key
 * @param {String} skey Secret Key
 * @param {String} akey Application Security Key
 * @param {String} sig_response Signature Response from Duo
 *
 * @param (String/Null} Returns a string containing the username if the response checks out. Returns null if it does not.
 *
 * @api public
 */
var verify_response = function (ikey, skey, akey, sig_response) {
  var parts = sig_response.split(':')
  if (parts.length !== 2) {
    return null
  }

  var auth_sig = parts[0]
  var app_sig = parts[1]
  var auth_user = _parse_vals(skey, auth_sig, AUTH_PREFIX, ikey)
  var app_user = _parse_vals(akey, app_sig, APP_PREFIX, ikey)

  if (auth_user !== app_user) {
    return null
  }

  return auth_user
}

module.exports = {
  'sign_request': sign_request,
  'verify_response': verify_response,
  'ERR_USER': ERR_USER,
  'ERR_IKEY': ERR_IKEY,
  'ERR_AKEY': ERR_AKEY,
  'ERR_SKEY': ERR_SKEY,
  'UsernameError': UsernameError,
  'IkeyError': IkeyError,
  'AkeyError': AkeyError
}
