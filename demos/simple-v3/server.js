let http = require('http')
let url = require('url')
let fs = require('fs')
let path = require('path')
let qs = require('querystring')
let duo_web = require('../../index.js')
let {Frame} = require('@duosecurity/duo_api/lib/Frame')

const IKEY = ''
const SKEY = ''
const AKEY = ''
const API_HOSTNAME = ''

let version = '2.0.0'
let version_string = `simple demo ${version}`
/**
 * Returns templated string with api_hostname and sig_request.
 *
 * @param {string} api_hostname - name of users API Hostname
 * @param {string} sig_request - Signed request returned from Duo's sign_request
 * to by the IFrame
 */
let IFrame = (api_hostname, init_txid) => {
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
              data-host=${api_hostname}
              data-init-txid=${init_txid}
              >
      </iframe>
      <script src='Duo-Web-v3.js'></script>
    </body>
  </html>`
}

let client = new Frame(IKEY, SKEY, API_HOSTNAME)
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
        duo_web.initialize_auth(client, {username, ikey: IKEY, akey: AKEY, client_version: version_string}, function (resp) {
          var txid = resp.response.txid
          // shows the IFrame
          let duo_frame = IFrame(API_HOSTNAME, txid)
          res.writeHead(200, {'Content-Type': 'text/html'})
          res.end(duo_frame)
        })
      } else {
        res.writeHead(404, {'Content-Type': 'text/html'})
        res.end(`Make sure you add a username:  http://localhost:8080/?username=xxx,\
        and appropriate configuration variables (ikey, skey, etc.). `)
      }
    } else if (base_url === '/Duo-Web-v3.js') {
      var script = fs.readFileSync(path.join(__dirname, '/Duo-Web-v3.js'))
      res.end(script)
    }
  } else if (method === 'POST') {
    if (base_url === '/') {
      let request_body = ''

      req.on('data', data => {
        request_body += data.toString() // convert Buffer to string
      })

      req.on('end', () => {
        let form_data = qs.parse(request_body)
        let response_txid = form_data.response_txid
        // verifies that the signed response is legitimate
        duo_web.verify_auth(client, {response_txid, ikey: IKEY, akey: AKEY}, function (authenticated_username) {
          if (authenticated_username) {
            res.end(`${authenticated_username.response.uname}, You've Been Dual Authenticated using WebSDKv3 !`)
          } else {
            res.status(401).end()
          }
        })
      })
    }
  }
})

server.listen(8080, () => console.log('Simple app listening on port 8080'))
