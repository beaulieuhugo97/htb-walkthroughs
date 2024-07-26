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

Puisqu'il y a un serveur Apache, on scanne également les répertoires:
```bash
dirb http://10.129.52.52/
```
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
