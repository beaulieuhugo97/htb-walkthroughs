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
