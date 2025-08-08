nmap output:
```
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

gobuster output:
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/logout               (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 857]
/register             (Status: 200) [Size: 952]
```

nikto output:
```
+ HEAD nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
```

whatweb output:
```
Summary   : HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Matomo, nginx[1.18.0], Script
```

register request:
```
POST /register HTTP/1.1
Host: artificial.htb
Content-Length: 67
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/register
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=random4321&email=random4321%40mail.net&password=random4321
```

login request:
```
POST /login HTTP/1.1
Host: artificial.htb
Content-Length: 47
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

email=random4321%40mail.net&password=random4321
```

dashboard request:
```
GET /dashboard HTTP/1.1
Host: artificial.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo3LCJ1c2VybmFtZSI6InJhbmRvbTQzMjEifQ.aJZgPw.oEFDyLs3mb8ucwx9O6sCQaq7uY4
Connection: keep-alive


```
