#!/bin/bash

ctf_name=$1
ip_address=$2
tld=${3:-ctf}
export IP=$ip_address
export CTF="$ctf_name.$tld"

echo Adding $IP to hosts as $CTF
echo "# IP from the $ctf_name CTF" | sudo tee -a /etc/hosts
echo "$IP $CTF" | sudo tee -a /etc/hosts

mkdir $ctf_name
export ctf_dir=$(readlink -f $ctf_name)
cd $ctf_dir
echo Created Directory: $ctf_dir
mkdir scans
echo Created Directory: $ctf_dir/scans
cat /home/kali/CTF/notes_template.md | sed "s/IPADDRESS/$ip_address/" | sed "s/CTFNAME/$ctf_name/" > $ctf_dir/notes.md
echo Created Notes File

cat /home/kali/CTF/checklist_template.md > $ctf_dir/checklist.md
echo Created Checklist File

echo "User: " >> $ctf_dir/flag.txt
echo "Root: " >> $ctf_dir/flag.txt
echo Created Flag File

echo Starting AutoRecon
cd scans
echo "Running autorecon -v $CTF in $(pwd)"
autorecon -v $CTF
echo AutoRecon complete
