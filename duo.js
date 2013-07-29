var crypto = require('crypto');

var DUO_PREFIX = "TX",
    APP_PREFIX = "APP",
    AUTH_PREFIX = "AUTH";

var DUO_EXPIRE = 300,
    APP_EXPIRE = 3600,
    IKEY_LEN = 20,
    SKEY_LEN = 40,
    AKEY_LEN = 40;

/* Exception Messages */
var ERR_USER = 'ERR|The username passed to sign_request() is invalid.',
    ERR_IKEY = 'ERR|The Duo integration key passed to sign_request() is invalid',
    ERR_SKEY = 'ERR|The Duo secret key passed to sign_request() is invalid',
    ERR_AKEY = 'ERR|The application secret key passed to sign_request() must be at least ' + String(AKEY_LEN) + ' characters.';

exports.ERR_USER = ERR_USER;
exports.ERR_IKEY = ERR_IKEY;
exports.ERR_SKEY = ERR_SKEY;
exports.ERR_AKEY = ERR_AKEY;

function _sign_vals(key, vals, prefix, expire) {
    var exp = Math.round((new Date()).getTime() / 1000) + expire;
    
    var val = vals + '|' + exp;
    var b64 = new Buffer(val).toString('base64');
    var cookie = prefix + '|' + b64;

    var sig = crypto.createHmac('sha1', key)
        .update(cookie)
        .digest('hex');
    
    return cookie + '|' + sig;
}

function _parse_vals(key, val, prefix) {
    var ts = Math.round((new Date()).getTime() / 1000);
    var parts = val.split('|');
    if (parts.length != 3) {
        return null;
    }

    var u_prefix = parts[0];
    var u_b64 = parts[1];
    var u_sig = parts[2];

    var sig = crypto.createHmac('sha1', key)
        .update(u_prefix + '|' + u_b64)
        .digest('hex');
    
    if (crypto.createHmac('sha1', key).update(sig).digest('hex') != crypto.createHmac('sha1', key).update(u_sig).digest('hex')) {
        return null;   
    }
    
    if (u_prefix != prefix) {
        return null;
    }    

    var cookie_parts = new Buffer(u_b64, 'base64').toString('utf8').split('|');
    if (cookie_parts.length != 3) {
        return null;
    }

    var user = cookie_parts[0];
    var ikey = cookie_parts[1];
    var exp = cookie_parts[2];

    if (ts >= parseInt(exp)) {
        return null
    }

    return user;
}

exports.sign_request = function (ikey, skey, akey, username) {
    if (!username || username.length < 1) {
        return ERR_USER;
    }
    if (!ikey || ikey.length != IKEY_LEN) {
        return ERR_IKEY;
    }
    if (!skey || skey.length != SKEY_LEN) {
        return ERR_SKEY;
    }
    if (!akey || akey.length < AKEY_LEN) {
        return ERR_AKEY;
    }

    var vals = username + '|' + ikey;

    var duo_sig = _sign_vals(skey, vals, DUO_PREFIX, DUO_EXPIRE);
    var app_sig = _sign_vals(akey, vals, APP_PREFIX, APP_EXPIRE);

    var sig_request = duo_sig + ':' + app_sig;
    return sig_request;
}

exports.verify_response = function (ikey, skey, akey, sig_response) {
    var parts = sig_response.split(':');
    if (parts.length != 2) {
        return null;
    }

    var auth_sig = parts[0];
    var app_sig = parts[1];
    var auth_user = _parse_vals(skey, auth_sig, AUTH_PREFIX);
    var app_user = _parse_vals(akey, app_sig, APP_PREFIX);

    if (auth_user != app_user) {
        return null;
    }

    return auth_user;
}
