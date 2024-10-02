nmap output:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-02 00:56 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Initiating Ping Scan at 00:56
Scanning permx.htb (10.129.27.161) [4 ports]
Completed Ping Scan at 00:56, 0.19s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 00:56
Scanning permx.htb (10.129.27.161) [1000 ports]
Discovered open port 80/tcp on 10.129.27.161
Discovered open port 22/tcp on 10.129.27.161
Completed SYN Stealth Scan at 00:56, 0.55s elapsed (1000 total ports)
Initiating Service scan at 00:56
Scanning 2 services on permx.htb (10.129.27.161)
Completed Service scan at 00:56, 6.48s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against permx.htb (10.129.27.161)
Retrying OS detection (try #2) against permx.htb (10.129.27.161)
Retrying OS detection (try #3) against permx.htb (10.129.27.161)
Retrying OS detection (try #4) against permx.htb (10.129.27.161)
Retrying OS detection (try #5) against permx.htb (10.129.27.161)
Initiating Traceroute at 00:56
Completed Traceroute at 00:56, 0.04s elapsed
Initiating Parallel DNS resolution of 1 host. at 00:56
Completed Parallel DNS resolution of 1 host. at 00:56, 0.00s elapsed
NSE: Script scanning 10.129.27.161.
Initiating NSE at 00:56
Completed NSE at 00:56, 1.23s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.14s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Nmap scan report for permx.htb (10.129.27.161)
Host is up (0.033s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: eLEARNING
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/2%OT=22%CT=1%CU=33113%PV=Y%DS=2%DC=T%G=Y%TM=66FC
OS:E0A5%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)
OS:OPS(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53C
OS:ST11NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
OS:ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%
OS:F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=
OS:Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Uptime guess: 42.629 days (since Tue Aug 20 09:51:12 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   32.50 ms 10.10.14.1
2   32.68 ms permx.htb (10.129.27.161)

NSE: Script Post-scanning.
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Initiating NSE at 00:56
Completed NSE at 00:56, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.48 seconds
           Raw packets sent: 1124 (53.482KB) | Rcvd: 1094 (47.790KB)
```

dirb output:
```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_output.txt
START_TIME: Wed Oct  2 01:03:32 2024
URL_BASE: http://permx.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://permx.htb/ ----
==> DIRECTORY: http://permx.htb/css/                                                                                                                           
==> DIRECTORY: http://permx.htb/img/                                                                                                                           
+ http://permx.htb/index.html (CODE:200|SIZE:36182)                                                                                                            
==> DIRECTORY: http://permx.htb/js/                                                                                                                            
==> DIRECTORY: http://permx.htb/lib/                                                                                                                           
+ http://permx.htb/server-status (CODE:403|SIZE:274)                                                                                                           
                                                                                                                                                               
---- Entering directory: http://permx.htb/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                               
---- Entering directory: http://permx.htb/img/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                               
---- Entering directory: http://permx.htb/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                                                               
---- Entering directory: http://permx.htb/lib/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Wed Oct  2 01:06:15 2024
DOWNLOADED: 4612 - FOUND: 2
```

ffuf output:
```bash
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Output file      : ffuf_output.json
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 15949
________________________________________________

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 1303ms]
www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 4573ms]
:: Progress: [114441/114441] :: Job [1/1] :: 1226 req/sec :: Duration: [0:01:43] :: Errors: 0 ::
```

nikto output:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.129.27.161
+ Target Hostname:    permx.htb
+ Target Port:        80
+ Start Time:         2024-10-02 00:59:02 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Server may leak inodes via ETags, header found with file /, inode: 8d56, size: 60f61d7bd0f80, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS .
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /lib/: Directory indexing found.
+ /lib/: This might be interesting.
+ /LICENSE.txt: License file found may identify site software.
+ 7962 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2024-10-02 01:03:49 (GMT-5) (287 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

![image](https://github.com/user-attachments/assets/319f2b71-0ff4-4367-a714-5e959dd8561b)

