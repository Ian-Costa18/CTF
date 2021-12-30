#!/bin/bash

ctf_name=$1
ctf_dir=~/CTF/$ctf_name
ip_address=$2
export IP=$ip_address

echo Adding $IP to hosts as $ctf_name.ctf
echo "# IP from the $ctf_name CTF" | sudo tee -a /etc/hosts
echo "$IP $ctf_name.ctf" | sudo tee -a /etc/hosts

mkdir $ctf_dir
cd $ctf_dir
echo Created Directory: $ctf_dir
mkdir scans
echo Created Directory: $ctf_dir/scans
cat /home/kali/CTF/notes_template.md | sed "s/IPADDRESS/$ip_address/" | sed "s/CTFNAME/$ctf_name/" > $ctf_dir/notes.md
echo Created Notes File

cat /home/kali/CTF/checklist_template.md > $ctf_dir/checklist.md

echo Starting AutoRecon
cd scans
autorecon -v $ctf_name.ctf

