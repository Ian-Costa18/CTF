# Penetration Testing Checklist

---

# Web

## Enumeration
- [ ] Nikto Scan
- [ ] HTML Analysis
	- [ ] HTML Comments
	- [ ] JavaScript
	- [ ] Network
- [ ] Stack
	- [ ] HTTP Headers
	- [ ] Favicon (https://wiki.owasp.org/index.php/OWASP_favicon_database)
	- [ ] Wappalyzer/BuiltWith

### Hidden Pages
- [ ] Feroxbuster (feroxbuster --url $url:$port --wordlist $wl -x ext)
- [ ] robots.txt
- [ ] sitemap.xml
- [ ] OSINT
	- [ ] Google Dorks
	- [ ] Archive (web.archive.org)

### Subdomains
- [ ] Certificate Search
- [ ] Sublist3r
- [ ] DNSRecon
- [ ] Virtual Hosts (ffuf -w $wl -H "Host: FUZZ.domain.tld" -u http://ip -fs {size})

## Exploitation

### Login Page
- tryhackme.com/room/authenticationbypass
- [ ] Default Credentials
- [ ] Brute Force
	- [ ] Username Enumeration (ffuf -w $wl -X POST -d "username=FUZZ&password=x" -H $headers -u $url -mr "username already exists")
	- [ ] Email Enumeration (See Username Enumeration, change to password reset forms) *NOISY*
- [ ] Logic Flaws
- [ ] Cookie Tampering

### File Inclusion
- tryhackme.com/room/fileinc
- [ ] Enumerate Parameters, POST Data, and Cookies
- [ ] Directory Traversal
- [ ] Local File Inclusion
- [ ] Remote File Inclusion
- [ ] Base64 Encode (php://filter/convert.base64-encode/resource=)

### Server-Side Request Forgery
- tryhackme.com/room/ssrfqi
- requestbin.com
- [ ] Filter Bypass
	- [ ] Deny List (Use alt localhost)
	- [ ] Allow List (Create malicious subdomain)
	- [ ] Open Redirect (Payload points to page which redirects to another website)
- [ ] Check Cloud IP (169.254.169.254)

### Cross-Site Scripting (XSS)
- [ ] Reflected XSS
- [ ] Stored XSS
- [ ] DOM Based XSS
- [ ] Blind XSS
	- TryHackMe 10.10.10.100
	- xsshunter.com

---

# Windows

## Priv Esc
- [ ] PowerUp
- [ ] winPEAS
- [ ] Metasploit Suggester (post/multi/recon/local_exploit_suggester)
- [ ] Token Impersonation

---

# Linux

## Priv Esc
- [ ] LinEnum
- [ ] linPEAS
- [ ] Metasploit Suggester (post/multi/recon/local_exploit_suggester)

## Container Escape
- [ ] Check linPEAS for containers
- [ ] Auto-Escape with CDK (github.com/cdk-team/CDK)
- [ ] Check for Scripts being ran from host