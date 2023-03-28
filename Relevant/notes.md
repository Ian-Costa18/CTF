# Relevant

**CTF Domain: Relevant.ctf**

## Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

    User.txt
    Root.txt

Additionally, the client has provided the following scope allowances:

    Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
    Locate and note all vulnerabilities found
    Submit the flags discovered to the dashboard
    Only the IP address assigned to your machine is in scope
    Find and report ALL vulnerabilities (yes, there is more than one path to root)

## Scans

```
Nmap scan report for Relevant.ctf (10.10.158.253)
Host is up, received syn-ack (0.12s latency).
Scanned at 2022-02-02 12:39:06 EST for 0s

PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
49663/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack
```

## Eumeration

Port 80 open, IIS Windows Server homepage?

Summary   : X-Powered-By[ASP.NET], HTTPServer[Microsoft-IIS/10.0], Microsoft-IIS[10.0]

Version: Microsoft IIS 10.0, searchsploit found no known exploits

SMB server on port 445, share "//Relevant.ctf/nt4wrksv" open to read/write access:

```
smbclient //Relevant.ctf/nt4wrksv -U guest
```

passwords.txt file in the share, contains two encoded usernames:passwords

```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

Bob - PASS
Bill - PASS
```

Port 49663 open, HTTP server seemingly the same as :80

relevant.ctf:49663/aspnet_client/ - returns 200 but no content
<https://stackoverflow.com/questions/947047/what-is-the-aspnet-client-folder-in-my-asp-net-website>

relevant.ctf:49663/aspnet_client/system_web/4_0_30319/ found, meaning ISS version 4.0.30319

Port 3389 has RDP open, maybe we can log in through there?

Everything I tried didn't work, got multiple errors but none specifically said bad user/pass

One error did say Bill's credentials were expired

## Exploitation

Windows server looks vulnerable to EternalBlue (Windows Server 2016 Standard Evaluation 14393)

MSFConsole check does work, download the Python eternalblue exploit and follow guide

<https://null-byte.wonderhowto.com/how-to/manually-exploit-eternalblue-windows-server-using-ms17-010-python-exploit-0195414/>

Named Pipes:

```
[+] relevant.ctf:445 - Pipes: \netlogon, \lsarpc, \samr, \atsvc, \epmapper, \eventlog, \InitShutdown, \lsass, \LSM_API_service, \ntsvcs, \protected_storage, \scerpc, \srvsvc, \trkwks, \W32TIME_ALT, \wkssvc
```

NOTHING IS WORKING

IVE TRIED THE PYTHON SCRIPT AND METASPLOIT AND NEITHER OF THEM CAN CONNECT

PYTHON KEEPS GIVING TYPE ERROR: `TypeError: can only concatenate str (not "bytes") to str`

METASPLOIT GETS STUCK ON `Did not receive a response from exploit packet`

GIVING UP FOR NOW, PLEASE SEND HELP

Looked at the official writeup for a hint

I had an idea earlier to try to upload a reverse shell to the SMB server but I could not find a way to execute it

Turns out, the HTTP server on :49663 hosts the "nt4wrksv" folder, so we can upload a .aspx script and get command execution!

## Privilege Escalation

Meterpreter "getsystem" worked via Named Pipe Impersonation

This box has been very frusterating, I hope to come back to complete it manually but I do not have the patience for it now.
