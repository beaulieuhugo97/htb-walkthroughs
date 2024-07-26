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
        "value": "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
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
      "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"
    ],
    "http2": false,
    "client-cert": "",
    "client-key": ""
  }
}
```

On a donc trouvé l'hôte `crm.board.htb`.
Lorsqu'on accède à la page, on voit qu'il s'agit d'une page de login pour le CRM `Dolibarr 17.0.0`
En regardant sur `exploit-db.com` on trouve que la version `17.0.1` est vulnérable à une attaque XSS. Peut-être utile pour plus tard.

Avec ces informations en tête, on va tenter une attaque sur le login avec hydra.
Pour procéder, on va avoir besoin d'un example de requête de login. Nous allons donc l'intercepter avec burp.
```bash
POST /index.php?mainmenu=home HTTP/1.1
Host: crm.board.htb
Content-Length: 378
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://crm.board.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://crm.board.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: DOLSESSID_3dfbb778014aaf8a61e81abec91717e6f6438f92=56oa8fv9t9ajjnulagksl2q5u8
Connection: close

token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-3T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=admin&password=test
```
On reçoit comme réponse `Bad value for login or password`.

Une fois ces informations en main, on lance hydra:
```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -t 16 http-post-form://crm.board.htb/index.php?mainmenu=home:"token=f2d2a913edc0137d1066cb9907b3f382&actionlogin=login&loginfunction=loginfunction&backtopage=&tz=-6&tz_string=America%2FChicago&dst_observed=1&dst_first=2024-03-10T01%3A59%3A00Z&dst_second=2024-11-03T01%3A59%3A00Z&screenwidth=2048&screenheight=861&dol_hide_topmenu=&dol_hide_leftmenu=&dol_optimize_smallscreen=&dol_no_mouse_hover=&dol_use_jmobile=&username=^USER^&password=^PASS^:F=incorrect" -o hydra_results.txt
```

On va aussi scanner les répertoires du nouveau sous-domaine avec dirb:
```bash
dirb http://crm.board.htb/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Jul 26 17:16:19 2024
URL_BASE: http://crm.board.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://crm.board.htb/ ----
==> DIRECTORY: http://crm.board.htb/admin/                                     
==> DIRECTORY: http://crm.board.htb/api/                                       
==> DIRECTORY: http://crm.board.htb/asset/                                     
==> DIRECTORY: http://crm.board.htb/bookmarks/                                 
==> DIRECTORY: http://crm.board.htb/categories/                                
==> DIRECTORY: http://crm.board.htb/comm/                                      
+ http://crm.board.htb/conf (CODE:403|SIZE:278)                                
==> DIRECTORY: http://crm.board.htb/contact/                                   
==> DIRECTORY: http://crm.board.htb/core/                                      
==> DIRECTORY: http://crm.board.htb/cron/                                      
==> DIRECTORY: http://crm.board.htb/custom/                                    
==> DIRECTORY: http://crm.board.htb/dav/                                       
==> DIRECTORY: http://crm.board.htb/exports/                                   
+ http://crm.board.htb/favicon.ico (CODE:200|SIZE:2238)                        
==> DIRECTORY: http://crm.board.htb/ftp/                                       
==> DIRECTORY: http://crm.board.htb/holiday/                                   
==> DIRECTORY: http://crm.board.htb/imports/                                   
==> DIRECTORY: http://crm.board.htb/includes/                                  
+ http://crm.board.htb/index.php (CODE:200|SIZE:6360)                          
==> DIRECTORY: http://crm.board.htb/install/                                   
==> DIRECTORY: http://crm.board.htb/langs/                                     
==> DIRECTORY: http://crm.board.htb/paypal/                                    
==> DIRECTORY: http://crm.board.htb/product/                                   
==> DIRECTORY: http://crm.board.htb/public/                                    
==> DIRECTORY: http://crm.board.htb/resource/                                  
+ http://crm.board.htb/robots.txt (CODE:200|SIZE:146)                          
+ http://crm.board.htb/server-status (CODE:403|SIZE:278)                       
==> DIRECTORY: http://crm.board.htb/support/                                   
==> DIRECTORY: http://crm.board.htb/theme/                                     
==> DIRECTORY: http://crm.board.htb/ticket/                                    
==> DIRECTORY: http://crm.board.htb/user/                                      
==> DIRECTORY: http://crm.board.htb/webservices/                               
==> DIRECTORY: http://crm.board.htb/website/                                   
                                                                               
---- Entering directory: http://crm.board.htb/admin/ ----
+ http://crm.board.htb/admin/index.php (CODE:200|SIZE:6366)                    
==> DIRECTORY: http://crm.board.htb/admin/menus/                               
==> DIRECTORY: http://crm.board.htb/admin/system/                              
==> DIRECTORY: http://crm.board.htb/admin/tools/                               
                                                                               
---- Entering directory: http://crm.board.htb/api/ ----
==> DIRECTORY: http://crm.board.htb/api/admin/                                 
==> DIRECTORY: http://crm.board.htb/api/class/                                 
+ http://crm.board.htb/api/index.php (CODE:200|SIZE:103)                       
                                                                               
---- Entering directory: http://crm.board.htb/asset/ ----
==> DIRECTORY: http://crm.board.htb/asset/admin/                               
==> DIRECTORY: http://crm.board.htb/asset/class/                               
==> DIRECTORY: http://crm.board.htb/asset/model/                               
==> DIRECTORY: http://crm.board.htb/asset/tpl/                                 
                                                                               
---- Entering directory: http://crm.board.htb/bookmarks/ ----
==> DIRECTORY: http://crm.board.htb/bookmarks/admin/                           
==> DIRECTORY: http://crm.board.htb/bookmarks/class/                           
                                                                               
---- Entering directory: http://crm.board.htb/categories/ ----
==> DIRECTORY: http://crm.board.htb/categories/admin/                          
==> DIRECTORY: http://crm.board.htb/categories/class/                          
+ http://crm.board.htb/categories/index.php (CODE:200|SIZE:6371)               
+ http://crm.board.htb/categories/info.php (CODE:200|SIZE:6370)                
                                                                               
---- Entering directory: http://crm.board.htb/comm/ ----
==> DIRECTORY: http://crm.board.htb/comm/action/                               
==> DIRECTORY: http://crm.board.htb/comm/admin/                                
+ http://crm.board.htb/comm/index.php (CODE:200|SIZE:6365)                     
==> DIRECTORY: http://crm.board.htb/comm/mailing/                              
                                                                               
---- Entering directory: http://crm.board.htb/contact/ ----
==> DIRECTORY: http://crm.board.htb/contact/class/                             
+ http://crm.board.htb/contact/info.php (CODE:200|SIZE:6367)                   
                                                                               
---- Entering directory: http://crm.board.htb/core/ ----
==> DIRECTORY: http://crm.board.htb/core/ajax/                                 
==> DIRECTORY: http://crm.board.htb/core/boxes/                                
==> DIRECTORY: http://crm.board.htb/core/class/                                
==> DIRECTORY: http://crm.board.htb/core/data/                                 
==> DIRECTORY: http://crm.board.htb/core/db/                                   
==> DIRECTORY: http://crm.board.htb/core/js/                                   
==> DIRECTORY: http://crm.board.htb/core/lib/                                  
==> DIRECTORY: http://crm.board.htb/core/login/                                
==> DIRECTORY: http://crm.board.htb/core/menus/                                
==> DIRECTORY: http://crm.board.htb/core/modules/                              
==> DIRECTORY: http://crm.board.htb/core/tpl/                                  
                                                                               
---- Entering directory: http://crm.board.htb/cron/ ----
==> DIRECTORY: http://crm.board.htb/cron/admin/                                
==> DIRECTORY: http://crm.board.htb/cron/class/                                
+ http://crm.board.htb/cron/info.php (CODE:200|SIZE:6364)                      
                                                                               
---- Entering directory: http://crm.board.htb/custom/ ----
                                                                               
---- Entering directory: http://crm.board.htb/dav/ ----
                                                                               
---- Entering directory: http://crm.board.htb/exports/ ----
==> DIRECTORY: http://crm.board.htb/exports/class/                             
+ http://crm.board.htb/exports/index.php (CODE:200|SIZE:6368)                  
                                                                               
---- Entering directory: http://crm.board.htb/ftp/ ----
==> DIRECTORY: http://crm.board.htb/ftp/admin/                                 
+ http://crm.board.htb/ftp/index.php (CODE:200|SIZE:6364)                      
                                                                               
---- Entering directory: http://crm.board.htb/holiday/ ----
==> DIRECTORY: http://crm.board.htb/holiday/class/                             
==> DIRECTORY: http://crm.board.htb/holiday/img/                               
+ http://crm.board.htb/holiday/info.php (CODE:200|SIZE:6367)                   
                                                                               
---- Entering directory: http://crm.board.htb/imports/ ----
==> DIRECTORY: http://crm.board.htb/imports/class/                             
+ http://crm.board.htb/imports/index.php (CODE:200|SIZE:6368)                  
                                                                               
---- Entering directory: http://crm.board.htb/includes/ ----
==> DIRECTORY: http://crm.board.htb/includes/ckeditor/                         
==> DIRECTORY: http://crm.board.htb/includes/fonts/                            
==> DIRECTORY: http://crm.board.htb/includes/jquery/                           
                                                                               
---- Entering directory: http://crm.board.htb/install/ ----
+ http://crm.board.htb/install/index.php (CODE:200|SIZE:501)                   
==> DIRECTORY: http://crm.board.htb/install/lib/                               
==> DIRECTORY: http://crm.board.htb/install/medias/                            
==> DIRECTORY: http://crm.board.htb/install/mssql/                             
==> DIRECTORY: http://crm.board.htb/install/mysql/                             
==> DIRECTORY: http://crm.board.htb/install/pgsql/                             
+ http://crm.board.htb/install/phpinfo.php (CODE:200|SIZE:501)                 
+ http://crm.board.htb/install/robots.txt (CODE:200|SIZE:25)                   
                                                                               
---- Entering directory: http://crm.board.htb/langs/ ----
==> DIRECTORY: http://crm.board.htb/langs/de_DE/                               
==> DIRECTORY: http://crm.board.htb/langs/en_US/                               
==> DIRECTORY: http://crm.board.htb/langs/es_ES/                               
==> DIRECTORY: http://crm.board.htb/langs/fr_FR/                               
==> DIRECTORY: http://crm.board.htb/langs/it_IT/                               
==> DIRECTORY: http://crm.board.htb/langs/ja_JP/                               
==> DIRECTORY: http://crm.board.htb/langs/ko_KR/                               
==> DIRECTORY: http://crm.board.htb/langs/pt_BR/                               
==> DIRECTORY: http://crm.board.htb/langs/zh_CN/                               
==> DIRECTORY: http://crm.board.htb/langs/zh_TW/                               
                                                                               
---- Entering directory: http://crm.board.htb/paypal/ ----
==> DIRECTORY: http://crm.board.htb/paypal/admin/                              
==> DIRECTORY: http://crm.board.htb/paypal/img/                                
==> DIRECTORY: http://crm.board.htb/paypal/lib/                                
                                                                               
---- Entering directory: http://crm.board.htb/product/ ----
==> DIRECTORY: http://crm.board.htb/product/admin/                             
==> DIRECTORY: http://crm.board.htb/product/ajax/                              
==> DIRECTORY: http://crm.board.htb/product/class/                             
+ http://crm.board.htb/product/index.php (CODE:200|SIZE:6368)                  
==> DIRECTORY: http://crm.board.htb/product/inventory/                         
==> DIRECTORY: http://crm.board.htb/product/stats/                             
==> DIRECTORY: http://crm.board.htb/product/stock/                             
                                                                               
---- Entering directory: http://crm.board.htb/public/ ----
==> DIRECTORY: http://crm.board.htb/public/agenda/                             
==> DIRECTORY: http://crm.board.htb/public/cron/                               
==> DIRECTORY: http://crm.board.htb/public/demo/                               
==> DIRECTORY: http://crm.board.htb/public/donations/                          
==> DIRECTORY: http://crm.board.htb/public/emailing/                           
+ http://crm.board.htb/public/index.php (CODE:302|SIZE:0)                      
==> DIRECTORY: http://crm.board.htb/public/members/                            
==> DIRECTORY: http://crm.board.htb/public/payment/                            
==> DIRECTORY: http://crm.board.htb/public/project/                            
==> DIRECTORY: http://crm.board.htb/public/test/                               
==> DIRECTORY: http://crm.board.htb/public/theme/                              
==> DIRECTORY: http://crm.board.htb/public/ticket/                             
==> DIRECTORY: http://crm.board.htb/public/website/                            
                                                                               
---- Entering directory: http://crm.board.htb/resource/ ----
==> DIRECTORY: http://crm.board.htb/resource/class/                            
                                                                               
---- Entering directory: http://crm.board.htb/support/ ----
+ http://crm.board.htb/support/index.php (CODE:200|SIZE:5617)                  
                                                                               
(!) FATAL: Too many errors connecting to host
    (Possible cause: OPERATION TIMEOUT)
                                                                               
-----------------
END_TIME: Fri Jul 26 18:07:29 2024
DOWNLOADED: 109742 - FOUND: 22

```

