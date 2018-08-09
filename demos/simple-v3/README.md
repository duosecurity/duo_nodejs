Demonstration of a simple Nodejs web server with Duo authentication using WebSDK 3 Authentication Flow.

# Configuration: #
To set up, add ikey, skey, akey, and hostname to server.js. For more
information regarding what these are, please visit https://duo.com/docs/duoweb.

Navigate to the root directory and run:
```
npm install
```
to install the @duosecurity/duo_api library from github.

# Run The Example: #
To run the server on port 8080:
```
node server.js
```

# Usage: #
Visit the root URL with a 'user' argument, e.g. 'http://localhost:8080/?username=myname'.
