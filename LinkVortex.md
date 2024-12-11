nmap output:
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
|_http-generator: Ghost 5.58
|_http-server-header: Apache
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
| http-title: BitByBit Hardware
|_Requested resource was http://linkvortex.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

whatweb output:
```bash
WhatWeb report for http://linkvortex.htb
Status    : 200 OK
Title     : BitByBit Hardware
IP        : 10.129.210.105
Country   : RESERVED, ZZ

Summary   : Apache, HTML5, HTTPServer[Apache], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

nikto output:
```bash
---------------------------------------------------------------------------
+ Server: Apache
+ /: Retrieved x-powered-by header: Express.
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /robots.txt: Entry '/ghost/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 4 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ OPTIONS: Allowed HTTP Methods: POST, GET, HEAD .
+ /members/: Retrieved access-control-allow-origin header: *.
+ 7968 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2024-12-11 05:18:48 (GMT-6) (328 seconds)
---------------------------------------------------------------------------
```

robots.txt
```bash
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```
