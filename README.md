# Overview

**duo_nodejs** - Duo two-factor authentication for Node.js web applications

Duo provides simple two-factor authentication as a service via:

1.  Phone callback
2.  SMS-delivered one-time passcodes
3.  Duo mobile app to generate one-time passcodes
4.  Duo mobile app for smartphone push authentication
5.  Duo hardware token to generate one-time passcodes

This package allows a web developer to quickly add Duo's interactive, self-service, two-factor authentication to any web login form - without setting up secondary user accounts, directory synchronization, servers, or hardware.

What's here:

* `js` - Duo Javascript library, to be hosted by your webserver.
* `duo.js` - Duo Node.js SDK to be integrated with your web application
* `test.js` -  Unit tests for our SDK. Run using `nodeunit tests`

# Usage

Install by dropping duo_nodejs in node_modules and including it in your project.

```var Duo = require('duo_nodejs');```

Developer documentation: <http://www.duosecurity.com/docs/duoweb>

# Support

Questions? Join the duo_web mailing list at
<http://groups.google.com/group/duo_web>

Report any bugs, feature requests, etc. to us directly:
<https://github.com/duosecurity/duo_nodejs/issues>

Have fun!

<http://www.duosecurity.com>
