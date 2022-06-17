# Deprecation Notice

Duo Security will deprecate and archive this repository on July 18, 2022. The repository will remain public and visible after that date, and integrations built using this repository’s code will continue to work. You can also continue to fork, clone, or pull from this repository after it is deprecated.

However, Duo will not provide any further releases or enhancements after the deprecation date.

Duo recommends migrating your application to the Duo Universal Prompt. Refer to [our documentation](https://duo.com/docs/universal-prompt-update-guide) for more information on how to update.

For frequently asked questions about the impact of this deprecation, please see the [Repository Deprecation FAQ](https://duosecurity.github.io/faq.html)

----

# Overview

[![Build Status](https://github.com/duosecurity/duo_nodejs/workflows/Node%20CI/badge.svg)](https://github.com/duosecurity/duo_nodejs/actions)
[![Issues](https://img.shields.io/github/issues/duosecurity/duo_nodejs)](https://github.com/duosecurity/duo_nodejs/issues)
[![Forks](https://img.shields.io/github/forks/duosecurity/duo_nodejs)](https://github.com/duosecurity/duo_nodejs/network/members)
[![Stars](https://img.shields.io/github/stars/duosecurity/duo_nodejs)](https://github.com/duosecurity/duo_nodejs/stargazers)
[![License](https://img.shields.io/badge/License-View%20License-orange)](https://github.com/duosecurity/duo_nodejs/blob/master/LICENSE)

**duo_nodejs** - Duo two-factor authentication for Node.js web applications: https://duo.com/docs/duoweb-v2

This package allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any web login form - without setting up secondary user accounts, directory synchronization, servers, or hardware.

Files located in the `js` directory should be hosted by your webserver for inclusion in web pages.

# Installing

Development:

```
$ git clone https://github.com/duosecurity/duo_nodejs.git
$ cd duo_nodejs
$ npm install
```

System:

```
$ npm install --global @duosecurity/duo_web
```

Or run the following to add to your project:

```
$ npm install --save @duosecurity/duo_web
```

# Using

```
$ node --interactive
> const duo_web = require('@duosecurity/duo_web');
> duo_web.sign_request(ikey, skey, akey, username);
'TX|...TX_SIGNATURE...==|...TX_HASH...:APP|...APP_SIGNATURE...==|...APP_HASH...'
```

# Test

```
$ npm run test
...
OK: 13 assertions (42ms)
```

# Lint

```
$ npm run lint

> @duosecurity/duo_web@1.0.3 lint duo_nodejs
> eslint duo.js index.js tests/
```

# Support

Report any bugs, feature requests, etc. to us directly: support@duosecurity.com

