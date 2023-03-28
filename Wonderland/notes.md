# Wonderland

**CTF Domain: Wonderland.ctf**

## Scans

```rustscan -a Wonderland.ctf```

## Eumeration

Directory enum finds wonderland.ctf/r/a/b/b/i/t

In the source code of the website, a username and password is found for the alice user

`alice:PASS`

## Exploitation

After logging in through ssk, there's a .py file that imports the "random" Python library

Using `sudo -l` we can see this file can be ran using sudo but only with the rabbit user

In Python, modules in the same directory are loaded before modules in the /usr/lib/pythonx.x path

Creating a file called `random.py` and inserting a shell in it, we can use sudo to run it as the rabbit user

`sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`

Now we are the rabbit user, we have a file called `teaParty` in our home directory

Using `strings`, we can see this has setuid, it's likely running as another user

We can also see that it's running the `date` command with a relative path

Creating a simple reverse shell, uploading it, renaming it to `date`, and adding the current directory to our path hijacks the command

The reverse shell is executed as the hatter user, which has his password in his home directory

`hatter:PASS`

Running `getcap -r / 2>/dev/null` as hatter shows we can run `perl`  as root

Using <https://gtfobins.github.io/gtfobins/perl/#capabilities> gives us a very easy command to run, which gets us the user and root flag!

Oops, looks like I could've just gotten the user flag by running `cat /root/user.txt` as hatter, no need to priv esc for that

## Privilege Escalation
