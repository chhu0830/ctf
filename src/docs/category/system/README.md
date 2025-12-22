# System
> [ShellSpells](https://www.shellspells.net/)

## Windows 🟦
> https://lolbas-project.github.io/

- Common Command

    | Run | Pannel |
    |-----|--------|
    | `control` | `控制台`
    | `ncpa.cpl` | `網路連線` |
    | `wf.msc` | `防火牆規則` |
    | `taskschd.msc` | `工作排程` |
    | `services.msc` | `服務` |
    | `winver` | 
    | `msinfo32` |

- `SET __COMPAT_LAYER=RunAsInvoker`
- Registry data reference to a dll file

    > [Understanding a negative offset of a registry data reference to a dll file](https://stackoverflow.com/questions/7350480/understanding-a-negative-offset-of-a-registry-data-reference-to-a-dll-file)
    > - Positive numbers are resource indices. Negative numbers (once you've removed the minus sign) are resource identifiers  
    > - `EmbedCtxt=@FirewallAPI.dll,-32252`

### File System
- NTFS Stream

    > [NTFS File Structure](https://www.researchgate.net/profile/Costas_Katsavounidis2/publication/363773832_Master_File_Table_MFT_on-disk_Structures_NTFS_31_httpsgithubcomkacos2000MFT_Browser/links/632da89086b22d3db4d9afad/Master-File-Table-MFT-on-disk-Structures-NTFS-31-https-githubcom-kacos2000-MFT-Browser.pdf)  
    > [NTFS Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3)  
    > [File Streams (Local File Systems)](https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams)  

    - `CMD$ fsutil file layout <file>`
    - Alternative Data Stream (ADS)

        ```powershell
        echo abc > note.txt:abc.txt
        echo C:\Windows\System32\cmd.exe > note.txt:cmd.exe
        dir /R

        wmic process call create note.txt:cmd.exe
        forfiles /M note.txt /C "note.txt:cmd.exe"

        Get-Content note.txt -stream abc.txt
        more < note.txt:abc.txt:$DATA
        ```

- Additional File Information
    - `CMD$ fsutil file queryEA <file>`
        - Extended Attribute
        - WSL metadata
    - `CMD$ fsutil file queryfileid <file>`
    - `PS$ (Get-Item filename).lastwritetime=(Get-Date "mm/dd/yyyy hh:mm am/pm")`

- File Naming

    > [Naming Files, Paths, and Namespaces | Microsoft](https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file)

    - Namespace
        - Win32 File Namespace
            - `\\?\`

                > tells the Windows APIs to disable all string parsing and to send the string that follows it straight to the file system

            - `\\?\GLOBALROOT\Device\ConDrv\Console`

                > `\\?\GLOBALROOT` ensures that the path following it looks in the true root path of the system object manager and not a session-dependent path

        - Win32 Device Namespace
            - `\\.\`

                > access the Win32 device namespace instead of the Win32 file namespace

        - NT Namespace
            - `\??\` 

                > NT Object Manager paths that can look up DOS-style devices like drive letters
                >
                > 1. process's `DosDevices` table
                > 2. `\GLOBAL??` Object Manager directory
                >
                > A "fake" prefix which refers to per-user Dos devices
                >
                > ![file path handling, user / kernal mode](https://i.sstatic.net/LOeeO.png)

            - | Path         | Content             |
              |:-------------|:--------------------|
              | `\Global??\` | Win32 namespace     |
              | `\Device\`   | Named device object |

    - Reserved Name (`\Global??\`)

        | Filename | Meaning |
        |:----|:---------------------------|
        | CON | console (input and output) |
        | AUX | an auxiliary device. In CP/M 1 and 2, PIP used PUN: (paper tape punch) and RDR: (paper tape reader) instead of AUX: |
        | LST | list output device, usually the printer |
        | PRN | as LST:, but lines were numbered, tabs expanded and form feeds added every 60 lines |
        | NUL | null device, akin to /dev/null |
        | EOF | input device that produced end-of-file characters, ASCII 0x1A |
        | INP | custom input device, by default the same as EOF: |
        | OUT | custom output device, by default the same as NUL: |

### User Credential
- Hash Files
    - `C:\Windows\System32\config\SAM` (`HKLM\SAM`)

        > HKLM\SAM is encrypted by the boot key, which is stored in HKLM\SYSTEM.

        - Get the hash file

            ```
            reg save HKLM\SAM .\sam.reg
            reg save HKLM\SYSTEM .\system.reg
            ```

            ```
            vssadmin create shadow
            copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .\sam.reg
            copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .\system.reg
            ```

    - `C:\Windows\NTDS\NTDS.dit`

        - Get the hash file

            ```
            ntdsutil snapshot "activate instance ntds" create quit quit
            ntdsutil snapshot "mount {ce2f5901-022f-4c21-b266-b4c14db67749}" quit quit
            copy C:\$SNAP_202109081356_VOLUMEC$\windows\NTDS\ntds.dit C:\ntds.dit
            ntdsutil snapshot "unmount {ce2f5901-022f-4c21-b266-b4c14db67749}" "delete {ce2f5901-022f-4c21-b266-b4c14db67749}" quit quit
            ntdsutil snapshot "List All" quit quit
            ```

            ```
            vssadmin create shadow /for=C:
            copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\NTDS\ntds.dit C:\ntds.dit
            vssadmin delete shadows /for=C: /quiet
            ```

    - Logon Credential Cache
        - `HKLM\SECURITY\Cache`
            - cached AD logon credentials
        - `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:CachedLogonsCount`
            - control cache count

    - LSASS
        - Can be protected by Credential Guard (Starting in Windows 10)

            > LSA process communicates with LSAIso.exe, the isolated
              LSA process that is protected by using VBS, when
              Credential Guard is enabled.
            >
            > To verify if the guard is enabled, use
            > ```powershell
            > (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
            > ```

            - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard`
                - `EnableVirtualizationBasedSecurity`
                - `RequirePlatformSecurityFeatures`
            - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
                - `LsaCfgFlags`
        - Store plaintext password
            - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
                - `UseLogonCredential = 1`
        - Configuration
            - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
                - `RunAsPPL`
- Credential Manager
    - List
        - `cmdkey /list`
        - `vaultcmd /list`
        - `vaultcmd /listcreds:"<Vault Name>"`
    - File
        - `C:\Users\<user>\AppData\Roaming\Microsoft\Credntials`
        - `C:\Users\<user>\AppData\Local\Microsoft\Protect\<SID>`
        - `C:\Users\<user>\AppData\Local\Microsoft\Vault\<SID>`
        - `C;\Windows\ServiceProfiles\<Account>\Appdata\...`
- Security Group
    - Domain Admins
    - Enterprise Admins Group
    - Server Operators
    - Backup Operators
    - Account Operators
    - Domain Users
    - Domain Computers
    - Domain Controllers

- Security Support Provider (SSP)
    - `Kerberos SSP` `%Windir%\System32\kerberos.dll`
    - `NTLM SSP` `%Windir%\System32\msv1_0.dll`
    - `Digest SSP` `%Windir%\System32\Wdigest.dll`

### Active Directory (AD)
- Command
    - `$ Get-ADObject -Filter * -Properties *`  
    - `$ Get-ADObject -Filter {ObjectGUID -eq <GUID>} -Properties *`
- Event
    - `Security` `5137` `A directory service object was created`

### WMI
> **WMI** (Windows Management Instrumentation) is the Microsoft
> implementation of **WBEM** (Web-Based Enterprise Management), a set
> of specifications published by **DMTF** (Distributed Management Task
> Force) that define how resources modeled using **CIM** (Common
> Information Model) can be discovered, accessed and manipulated.

> [Windows Management Instrumentation | Microsoft](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)  
> [WMI Internals Part 1 | Jonathan Johnson](https://jsecurity101.medium.com/wmi-internals-part-1-41bb97e7f5eb)

- Architecture
    - WMI Provider

        > A COM object (COM server) that monitor managed objects, which are
        > logical or physical enterprise components, such as proccesses,
        > OS, or hard disk.
        > 
        > `C:\Windows\System32\wbem\*`

        - DLL

            > COM Object

        - MOF (Managed Object Format)

            > A definition for a WMI class.

    - WMI Infrastructure

        > svchosts.exe [Winmgmt service] (`C:\WINDOWS\system32\wbem\WMIsvc.dll`)
        >
        > Load appropriate WMI Provider (DLL) into WMI Provider Host
        > (WmiPrvSE, `C:\WINDOWS\system32\wbem\wmiprvse.exe`).

        - WMI Core (CIM Object Manager, CIMOM)

            > Act as the intermediary between the provider, management applications, and the WMI repository.

        - WMI Repository

            > Holding static data at `C:\Windows\System32\wbem\Repository\`, such as Classes.

    - WMI Consumer (Management Application)
        - wmic
        - powershell
        - wbemtest
        - WMI Explorer
- Command
    - List Namespace

        ```
        PS$ Get-CimInstance [-Namespace <namespace:(root/cimv2)>] -ClassName __NAMESPACE

        WQL$ SELECT * From __NAMESPACE
        ```

    - List Class

        ```
        PS$ Get-CimClass [-Namespace <namespace:(root/cimv2)>] [[-ClassName] <classname:(*)>]
        ```

    - List Instance

        ```
        PS$ Get-CimInstance [-Namespace <namespace:(root/cimv2)>] -ClassName <classname>

        CMD$ wmic [/namespace:<namespace:(\\root\cimv2)>] path <classname>

        WQL$ Select * From <classname>
        ```

    - Invoke CIM Method

        ```powershell
        PS$ Get-CimClass -MethodName *Create*

        PS$ (Get-CimInstance __Provider -Filter "Name = '$(([WmiClass] 'Win32_Process').Qualifiers['provider'].Value)'").CLSID
        {d63a5850-8f16-11cf-9f47-00aa00bf345c}

        PS$ Get-ItemPropertyValue -Path "Registry::HKEY_CLASSES_ROOT\CLSID\{d63a5850-8f16-11cf-9f47-00aa00bf345c}\InprocServer32\" -Name '(default)'"
        C:\WINDOWS\system32\wbem\cimwin32.dll

        PS$ (Get-CimClass -ClassName Win32_Process).CimClassMethods['Create'].Parameters
        PS$ type C:\Windows\System32\wbem\cimwin32.mof

        PS$ $Win32_ProcessStartupClass = Get-CimClass -ClassName Win32_ProcessStartup
        PS$ $ProcessStartupInformation = New-CimInstance -CimClass $Win32_ProcessStartupClass -Property @{'ShowWindow' = 0} -ClientOnly #0 = SW_HIDDEN
        PS$ Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='notepad.exe'; CurrentDirectory='C:\'; ProcessStartupInformation=$ProcessStartupInformation}'}
        ```

- Important Instance

    | Namespace | ClassName |
    |-----------|-----------|
    | `root/Microsoft/Windows/Defender` | `MSFT_MpComputerStatus` |
    | `root/SecurityCenter2` | `AntivirusProduct` |
    | `root/SecurityCenter2` | `FirewallProduct` |
    | `root/cimv2` | `Win32_Account` |
    | `root/cimv2` | `Win32_LoggedOnUser` |
    | `root/cimv2` | `Win32_Process` |


### Remote Command
- psexec
    - Make sure `\\<host>\admin$` can be accessed

    ```powershell
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    psexec \\host -u <user> -p <pass> -i [SessID] <cmd>
    ```

- wmic

    ```powershell
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh firewall set service remoteadmin enable
    wmic /node:<host> /user:<user> /password:<pass> process call create <cmd>
    ```

- winrm

### minifilter

### WFP
- `HKLM\System\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter\<GUID>`
- `HKLM\System\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Provider\<GUID>`
- `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\<GUID>`

### AMSI

### UWP (app container)


## Linux 🐧

### Open Port
- `sudo ip -all netns exec ss -ltnp`

## macOS 🍎
- Resource Fork
- Named Fork
- Data Fork
