Demonstration of a simple Nodejs web server with Duo authentication.

# Configuration: #
To set up, add ikey, skey, akey, hostname, and post_action to server.js. For more
information regarding what these are, please visit https://duo.com/docs/duoweb.

# Run The Example: #
To run the server on port 8080:
```
node server.js
```

# Usage: #
Visit the root URL with a 'user' argument, e.g. 'http://localhost:8080/?username=myname'.
