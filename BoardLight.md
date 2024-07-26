Tout d'abord on commence par un scan.
```bash
nmap -sV -v 10.129.52.52
```

On voit qu'il y a deux ports d'ouverts:
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: board.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

La version d'Apache ne semble pas avoir de vulnérabilités connues.
Puisqu'il y a un serveur Apache, on scanne également les répertoires:
```bash
dirb http://10.129.52.52/
```
La page `/server-status` semble intéressant, mais nous n'y avons pas accès.
En accédant à http://10.129.52.52/, on se rend compte qu'il s'agit d'un site php.
Plusieurs liens (comme le login) ne semblent pas fonctionner.

Aucune requête POST n'apparaît dans sur le réseau lors de l'envoi d'un formulaire.
En regardant plus loin, voici un example de form:
```html
<form action="">
  <div>
    <input type="text" placeholder="Full Name ">
  </div>
  <div>
    <input type="text" placeholder="Phone Number">
  </div>
  <div>
    <input type="email" placeholder="Email Address">
  </div>
  <div>
    <input type="text" placeholder="Message" class="input_message">
  </div>
  <div class="d-flex justify-content-center">
    <button type="submit" class="btn_on-hover">
      Send
    </button>
  </div>
</form>
```
On constate que le champ `action` est vide.

Si on tente d'accéder à une page qui n'existe pas, par exemple `/login.php`, on obtient `File not found.`
On tente donc de faire du directory traversal pour afficher `/etc/passwd` mais sans succès, l'url est corrigée et on obtient `The requested URL was not found on this server.`.

Aucun cookie n'est visible.
La version de jQuery, `3.4.1` ne semble pas avoir de faille connues.

En cherchant .php dans le code source de la page un fichier `portfolio.php` qui est commenté.
Malheureusement accéder au fichier donne un `File not found.`

On continue l'énumération avec nikto mais rien de bien intéressant.
```bash
nikto -h http://10.129.52.52/

+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ 8074 requests: 0 error(s) and 4 item(s) reported on remote host
```

En désespoir de cause, on tente l'énumération des sous-domaines avec gobuster.
D'abord, il faut télécharger les listes de sous-domaines:
```bash
wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip \
  && unzip SecList.zip \
  && rm -f SecList.zip
```

Puis, on lance l'énumération avec ffuf:
```bash
ffuf -w ./SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H "Host: FUZZ.board.htb" -mc 200 -fs 15949 -o ffuf_output.json -of json
```
On obtient le résultat suivant:

```json
{
  "commandline": "ffuf -w ./SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H Host: FUZZ.board.htb -mc 200 -fs 15949 -o ffuf_output.txt -of json",
  "time": "2024-07-26T17:05:30-05:00",
  "results": [
    {
      "input": {
        "FFUFHASH": "6790a48",
        "FUZZ": "crm"
      },
      "position": 72,
      "status": 200,
      "length": 6360,
      "words": 397,
      "lines": 150,
      "content-type": "text/html; charset=UTF-8",
      "redirectlocation": "",
      "scraper": {},
      "duration": 93789337,
      "resultfile": "",
      "url": "http://board.htb",
      "host": "crm.board.htb"
    }
  ],
  "config": {
    "autocalibration": false,
    "autocalibration_keyword": "FUZZ",
    "autocalibration_perhost": false,
    "autocalibration_strategies": [
      "basic"
    ],
    "autocalibration_strings": [],
    "colors": false,
    "cmdline": "ffuf -w ./SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H Host: FUZZ.board.htb -mc 200 -fs 15949 -o ffuf_output.txt -of json",
    "configfile": "",
    "postdata": "",
    "debuglog": "",
    "delay": {
      "value": "0.00"
    },
    "dirsearch_compatibility": false,
    "encoders": [],
    "extensions": [],
    "fmode": "or",
    "follow_redirects": false,
    "headers": {
      "Host": "FUZZ.board.htb"
    },
    "ignorebody": false,
    "ignore_wordlist_comments": false,
    "inputmode": "clusterbomb",
    "cmd_inputnum": 100,
    "inputproviders": [
      {
        "name": "wordlist",
        "keyword": "FUZZ",
        "value": "/home/bhugo97/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt",
        "encoders": "",
        "template": ""
      }
    ],
    "inputshell": "",
    "json": false,
    "matchers": {
      "IsCalibrated": false,
      "Mutex": {},
      "Matchers": {
        "status": {
          "value": "200"
        }
      },
      "Filters": {
        "size": {
          "value": "15949"
        }
      },
      "PerDomainFilters": {}
    },
    "mmode": "or",
    "maxtime": 0,
    "maxtime_job": 0,
    "method": "GET",
    "noninteractive": false,
    "outputdirectory": "",
    "outputfile": "ffuf_output.txt",
    "outputformat": "json",
    "OutputSkipEmptyFile": false,
    "proxyurl": "",
    "quiet": false,
    "rate": 0,
    "raw": false,
    "recursion": false,
    "recursion_depth": 0,
    "recursion_strategy": "default",
    "replayproxyurl": "",
    "requestfile": "",
    "requestproto": "https",
    "scraperfile": "",
    "scrapers": "all",
    "sni": "",
    "stop_403": false,
    "stop_all": false,
    "stop_errors": false,
    "threads": 40,
    "timeout": 10,
    "url": "http://board.htb",
    "verbose": false,
    "wordlists": [
      "/home/bhugo97/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt"
    ],
    "http2": false,
    "client-cert": "",
    "client-key": ""
  }
}
```
