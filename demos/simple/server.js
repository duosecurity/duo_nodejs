let http = require('http')
let url = require('url')
let qs = require('querystring')
let duo_web = require('../../index.js')

const ikey = ''
const skey = ''
const akey = ''
const api_hostname = ''
const post_action = ''

/**
 * Returns templated string with api_hostname and sig_request.
 *
 * @param {string} api_hostname - name of users API Hostname
 * @param {string} sig_request - Signed request returned from Duo's sign_request
 * @param {string} post_action - Name of the post_action url that will be posted
 * to by the IFrame
 */
let IFrame = (api_hostname, sig_request, post_action) => {
  return `<!DOCTYPE html>
  <html>
    <head>
      <title>Duo Authentication Prompt</title>
      <meta name='viewport' content='width=device-width, initial-scale=1'>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <style>
        body {
            text-align: center;
        }

        iframe {
            width: 100%;
            min-width: 304px;
            max-width: 620px;
            height: 330px;
            border: none;
        }
      </style>
    </head>
    <body>
      <h1>Duo Authentication Prompt</h1>
      <iframe id="duo_iframe"
              title="Two-Factor Authentication"
              data-host= ${api_hostname}
              data-sig-request= ${sig_request}
              data-post-action=${post_action}
              >
      </iframe>
      <script src='https://api.duosecurity.com/frame/hosted/Duo-Web-v2.min.js'></script>
    </body>
  </html>`
}

/**
 * Creates the server and listens for any POST/GET requests.
 */
const server = http.createServer((req, res) => {
  let base_url = url.parse(req.url).pathname
  let method = req.method
  if (method === 'GET') {
    if (base_url === '/') {
      let query = url.parse(req.url, true).query
      let {username} = query
      if (username) {
        // initializes secondary authentication process
        let sig_request = duo_web.sign_request(ikey, skey, akey, username)
        let duo_frame = IFrame(api_hostname, sig_request, post_action)
        // shows the IFrame
        res.writeHead(200, {'Content-Type': 'text/html'})
        res.end(duo_frame)
      } else {
        res.writeHead(404, {'Content-Type': 'text/html'})
        res.end(`Make sure you add a username:  http://localhost:8080/?username=xxx,\
        and appropriate configuration variables (ikey, skey, etc.). `)
      }
    }
  } else if (method === 'POST') {
    if (base_url === post_action) {
      let request_body = ''

      req.on('data', data => {
        request_body += data.toString() // convert Buffer to string
      })

      req.on('end', () => {
        let form_data = qs.parse(request_body)
        let sig_response = form_data.sig_response
        // verifies that the signed response is legitimate
        let authenticated_username = duo_web.verify_response(ikey, skey, akey, sig_response)
        if (authenticated_username) {
          res.end(`${authenticated_username}, You've Been Dual Authenticated !`)
        } else {
          res.status(401).end()
        }
      })
    }
  }
})

server.listen(8080, () => console.log('Simple app listening on port 8080'))
