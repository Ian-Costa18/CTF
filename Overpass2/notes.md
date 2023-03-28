# Overpass2

**CTF Domain: Overpass2.ctf**

## Scans

```rustscan -a Overpass2.ctf```

## Eumeration

Backdoor SSH setup on port 2222

## Exploitation

Password found through hashcat:

'6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:**********`

Logging into backdoor SSH session gives user shell!

## Privilege Escalation

Hidden file ".suid_bash" found in home directory

After a lot of messing with it, `./.suid_bash -p` gives a root shell!
