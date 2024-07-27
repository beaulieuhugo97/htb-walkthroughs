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

En fouillant un peu sur le web, on trouve le CVE suivant:
```bash
https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253
https://github.com/dollarboysushil/Dolibarr-17.0.0-Exploit-CVE-2023-30253
```
