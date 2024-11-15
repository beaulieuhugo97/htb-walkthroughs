nmap output:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 10:53 CST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 10:53
Completed NSE at 10:53, 0.00s elapsed
Initiating NSE at 10:53
Completed NSE at 10:53, 0.00s elapsed
Initiating NSE at 10:53
Completed NSE at 10:53, 0.00s elapsed
Initiating Ping Scan at 10:53
Scanning sightless.htb (10.129.215.169) [4 ports]
Completed Ping Scan at 10:53, 0.05s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 10:53
Scanning sightless.htb (10.129.215.169) [1000 ports]
Discovered open port 80/tcp on 10.129.215.169
Discovered open port 21/tcp on 10.129.215.169
Discovered open port 22/tcp on 10.129.215.169
Completed SYN Stealth Scan at 10:53, 0.49s elapsed (1000 total ports)
Initiating Service scan at 10:53
Scanning 3 services on sightless.htb (10.129.215.169)
Completed Service scan at 10:54, 28.64s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against sightless.htb (10.129.215.169)
Retrying OS detection (try #2) against sightless.htb (10.129.215.169)
Retrying OS detection (try #3) against sightless.htb (10.129.215.169)
Retrying OS detection (try #4) against sightless.htb (10.129.215.169)
Retrying OS detection (try #5) against sightless.htb (10.129.215.169)
Initiating Traceroute at 10:54
Completed Traceroute at 10:54, 0.03s elapsed
Initiating Parallel DNS resolution of 1 host. at 10:54
Completed Parallel DNS resolution of 1 host. at 10:54, 0.00s elapsed
NSE: Script scanning 10.129.215.169.
Initiating NSE at 10:54
Completed NSE at 10:54, 10.31s elapsed
Initiating NSE at 10:54
Completed NSE at 10:54, 28.38s elapsed
Initiating NSE at 10:54
Completed NSE at 10:54, 0.00s elapsed
Nmap scan report for sightless.htb (10.129.215.169)
Host is up (0.029s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.215.169]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Sightless.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=11/15%Time=67377C9C%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,A3,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x2
SF:0Server\)\x20\[::ffff:10\.129\.215\.169\]\r\n500\x20Invalid\x20command:
SF:\x20try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20t
SF:ry\x20being\x20more\x20creative\r\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=11/15%OT=21%CT=1%CU=33225%PV=Y%DS=2%DC=T%G=Y%TM=673
OS:77CE0%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A
OS:)OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53
OS:CST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
OS:)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+
OS:%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A
OS:=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%D
OS:F=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=4
OS:0%CD=S)

Uptime guess: 24.580 days (since Mon Oct 21 21:59:40 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   29.06 ms 10.10.14.1
2   29.15 ms sightless.htb (10.129.215.169)

NSE: Script Post-scanning.
Initiating NSE at 10:54
Completed NSE at 10:54, 0.00s elapsed
Initiating NSE at 10:54
Completed NSE at 10:54, 0.00s elapsed
Initiating NSE at 10:54
Completed NSE at 10:54, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.90 seconds
           Raw packets sent: 1124 (53.442KB) | Rcvd: 1099 (48.135KB)
```

gobuster output:
```bash
/images               (Status: 301) [Size: 178] [--> http://sightless.htb/images/]
/icones               (Status: 301) [Size: 178] [--> http://sightless.htb/icones/]
/index.html           (Status: 200) [Size: 4993]
/.                    (Status: 200) [Size: 4993]
```

nikto output:
```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.129.215.169
+ Target Hostname:    sightless.htb
+ Target Port:        80
+ Start Time:         2024-11-15 10:56:02 (GMT-6)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 7962 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2024-11-15 11:00:12 (GMT-6) (250 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

whatweb output:
```bash
WhatWeb report for http://sightless.htb
Status    : 200 OK
Title     : Sightless.htb
IP        : 10.129.215.169
Country   : RESERVED, ZZ

Summary   : Email[sales@sightless.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Matomo, nginx[1.18.0], X-UA-Compatible[IE=edge]
```
