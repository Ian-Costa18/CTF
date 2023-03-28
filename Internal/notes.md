# Internal

**CTF Domain: Internal.ctf**

## Scans

```rustscan -a Internal.ctf```

```bash
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

Apache2 Ubuntu Default Page

Wordpress hosted on Internal.ctf/wordpress

PHPMyAdmin hosted on Internal.ctf/phpmyadmin

## Eumeration

WPScan found credentials for admin user!

```
[!] Valid Combinations Found:
 | Username: admin, Password: PASS
```

After login, an email verification page comes up with the email address `admin@internal.thm`

A private post has the credentials `william:PASS`

## Exploitation

Getting access to Wordpress allows us to upload a reverse shell using a plugin or theme.

Plugins seem to be read-only, thankfully the theme is editable.

Using metasploit, creating a PHP reverse shell is extreamly easy.

/usr/bin/gettext.sh

In /opt, a file called wp-save.txt contains the credentails for the user

`aubreanna:PASS`

Flag is in the home folder!

## Privilege Escalation

Also in the home folder is a file called jenkins.txt that states "Internal Jenkins service is running on 172.17.0.2:8080"

Running a reverse SSH tunnel allows us to use our browser to connect to it

`ssh -L 8888:172.17.0.2:8080 aubreanna@internal.ctf`

MSF Brute force module got us the credentials

`admin:PASS`

We can execute commands using the scripts endpoint <http://localhost:8888/script>

In the /opt directory, there's a note.txt file containing the credentials for the root user
