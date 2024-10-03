nmap output:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-02 23:58 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
Initiating Ping Scan at 23:58
Scanning sea.htb (10.129.3.193) [4 ports]
Completed Ping Scan at 23:58, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 23:58
Scanning sea.htb (10.129.3.193) [1000 ports]
Discovered open port 80/tcp on 10.129.3.193
Discovered open port 22/tcp on 10.129.3.193
Completed SYN Stealth Scan at 23:58, 0.21s elapsed (1000 total ports)
Initiating Service scan at 23:58
Scanning 2 services on sea.htb (10.129.3.193)
Completed Service scan at 23:58, 6.05s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against sea.htb (10.129.3.193)
Retrying OS detection (try #2) against sea.htb (10.129.3.193)
Retrying OS detection (try #3) against sea.htb (10.129.3.193)
Retrying OS detection (try #4) against sea.htb (10.129.3.193)
Retrying OS detection (try #5) against sea.htb (10.129.3.193)
Initiating Traceroute at 23:59
Completed Traceroute at 23:59, 0.01s elapsed
Initiating Parallel DNS resolution of 1 host. at 23:59
Completed Parallel DNS resolution of 1 host. at 23:59, 0.00s elapsed
NSE: Script scanning 10.129.3.193.
Initiating NSE at 23:59
Completed NSE at 23:59, 0.44s elapsed
Initiating NSE at 23:59
Completed NSE at 23:59, 0.06s elapsed
Initiating NSE at 23:59
Completed NSE at 23:59, 0.00s elapsed
Nmap scan report for sea.htb (10.129.3.193)
Host is up (0.0088s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Sea - Home
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/2%OT=22%CT=1%CU=37392%PV=Y%DS=2%DC=T%G=Y%TM=66FE
OS:2497%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10B%TI=Z%CI=Z%TS=C)SEQ(S
OS:P=100%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST11NW
OS:7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE88%
OS:W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CN
OS:NSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=
OS:Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=4
OS:0%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=
OS:G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 30.893 days (since Mon Sep  2 02:33:20 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT     ADDRESS
1   8.65 ms 10.10.14.1
2   8.86 ms sea.htb (10.129.3.193)

NSE: Script Post-scanning.
Initiating NSE at 23:59
Completed NSE at 23:59, 0.00s elapsed
Initiating NSE at 23:59
Completed NSE at 23:59, 0.00s elapsed
Initiating NSE at 23:59
Completed NSE at 23:59, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.52 seconds
           Raw packets sent: 1168 (57.488KB) | Rcvd: 1096 (47.854KB)
```

nikto output:
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.129.3.193
+ Target Hostname:    sea.htb
+ Target Port:        80
+ Start Time:         2024-10-03 00:00:40 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /home/: This might be interesting.
+ 7962 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2024-10-03 00:02:58 (GMT-5) (138 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

dirb output:
```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_output.txt
START_TIME: Wed Oct  2 23:59:28 2024
URL_BASE: http://sea.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://sea.htb/ ----
+ http://sea.htb/0 (CODE:200|SIZE:3650)                                                                                                                                                             
+ http://sea.htb/404 (CODE:200|SIZE:3341)                                                                                                                                                           
==> DIRECTORY: http://sea.htb/data/                                                                                                                                                                 
+ http://sea.htb/home (CODE:200|SIZE:3650)                                                                                                                                                          
+ http://sea.htb/index.php (CODE:200|SIZE:3650)                                                                                                                                                     
==> DIRECTORY: http://sea.htb/messages/                                                                                                                                                             
==> DIRECTORY: http://sea.htb/plugins/                                                                                                                                                              
+ http://sea.htb/server-status (CODE:403|SIZE:199)                                                                                                                                                  
==> DIRECTORY: http://sea.htb/themes/                                                                                                                                                               
                                                                                                                                                                                                    
---- Entering directory: http://sea.htb/data/ ----
+ http://sea.htb/data/404 (CODE:200|SIZE:3341)                                                                                                                                                      
==> DIRECTORY: http://sea.htb/data/files/                                                                                                                                                           
+ http://sea.htb/data/home (CODE:200|SIZE:3650)                                                                                                                                                     
                                                                                                                                                                                                    
---- Entering directory: http://sea.htb/messages/ ----
+ http://sea.htb/messages/404 (CODE:200|SIZE:3341)                                                                                                                                                  
+ http://sea.htb/messages/home (CODE:200|SIZE:3650)                                                                                                                                                 
                                                                                                                                                                                                    
---- Entering directory: http://sea.htb/plugins/ ----
+ http://sea.htb/plugins/404 (CODE:200|SIZE:3341)                                                                                                                                                   
+ http://sea.htb/plugins/home (CODE:200|SIZE:3650)                                                                                                                                                  
                                                                                                                                                                                                    
---- Entering directory: http://sea.htb/themes/ ----
+ http://sea.htb/themes/404 (CODE:200|SIZE:3341)                                                                                                                                                    
+ http://sea.htb/themes/home (CODE:200|SIZE:3650)                                                                                                                                                   
                                                                                                                                                                                                    
---- Entering directory: http://sea.htb/data/files/ ----
+ http://sea.htb/data/files/404 (CODE:200|SIZE:3341)                                                                                                                                                
+ http://sea.htb/data/files/home (CODE:200|SIZE:3650)                                                                                                                                               
                                                                                                                                                                                                    
-----------------
END_TIME: Thu Oct  3 00:05:09 2024
DOWNLOADED: 27672 - FOUND: 15
```

![image](https://github.com/user-attachments/assets/2ade61b0-b05b-4312-8ad3-bc6df62e1729)

python3 web server output:
```bash
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.129.3.193 - - [03/Oct/2024 00:21:38] "GET / HTTP/1.1" 200 -
```

burp request:
```bash
POST /contact.php HTTP/1.1
Host: sea.htb
Content-Length: 73
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://sea.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://sea.htb/contact.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ul837dk36hbbj5d15s6hm7hu3b
Connection: close

name=Name&email=email%40email.email&age=0&country=Country&website=http://10.10.14.46:4444/
```
