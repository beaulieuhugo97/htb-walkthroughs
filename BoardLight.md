Tout d'abord on commence par un scan.
```bash
nmap -sV -v 10.10.11.11
```

On voit qu'il y a deux ports d'ouverts:
```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: board.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On scanne également les répertoires:
```bash
dirb http://10.10.11.11/
```
