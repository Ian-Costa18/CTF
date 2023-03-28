# Boiler

**CTF Domain: Boiler.ctf**

## Scans

```rustscan -a Boiler.ctf```

## Eumeration

FTP has anonymous log in, only 1 file is accessable `.info.txt`

Contains a ROT-13 message that states: "Just wanted to see if you find it. Lol. Remember: Enumeration is the key!"

## Exploitation

In the Joomla install, there's a subdirectory called `_test` which contains sar2html, a web app that's vulnerable to remote code execution

I created a small Python script to have an easy to use shell.

There is a file called `log.txt` in the working directory that contains ssh credentials to the "basterd" user

`basterd:PASS`

SSH is on port 55007 so we need to use the -p flag to connect to it.

`ssh basterd@boiler.ctf -p 55007`

In the user's home directory, there's a file called `backup.sh` that contains the credentials for the `stoner` user

`stoner:PASS`

## Privilege Escalation

find has SUID set, using <https://gtfobins.github.io/gtfobins/find/#suid> we can easily get root

`./find . -exec /bin/sh -p \; -quit`
