## Send directory with `netcat`
###Sender:
```bash
tar -czf directory.tar.gz ./directory
cat directory.tar.gz | nc x.x.x.x 1234
```
###Receiver:
```bash
nc -l -p 1234 > directory.tar.gz
```
