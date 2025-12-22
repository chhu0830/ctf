# Forensic
> [Windows Forensic Handbook](https://psmths.gitbook.io/windows-forensics)

## Malware Scanner
- [Microsoft Safety Scanner](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)
- [MSRT (Windows Malicious Software Removal Tool)](https://www.microsoft.com/en-us/download/details.aspx?id=9905)
- [Trend Micro Anti-Threat Toolkit](https://www.trendmicro.com/zh_tw/business/capabilities/solutions-for/ransomware/free-tools.html)
- [VirusTotal](https://www.virustotal.com/gui/)
- [nodistribute](https://nodistribute.com/)

## Artifact
- Sysinternals (`https://live.sysinternals.com/` `\\live.sysinternals.com\tools\`)

### File
- Disk Forensic
    - autopsy
    - OSForensic / OSFClone
    - FTK Imager
    - Sleuth Kit
- Search
    - `CMD$ forfile`
    - `CMD$ dir /s *filename*`
    - `SH$ find -name *filename*`
    - `SH$ find -perm /4000`
    - `SH$ find -mtime +3`
- Directory
    - `C:\$Recycle.Bin`

### Registry
- Query 
    - `PS$ dir "Registry::HKLM\"`
- Essential Registry

    | Path | Description |
    |------|-------------|
    | `HKLM\System\CurrentControlSet\Control\HiveList` | reg file location |
    | `{HKLM\|HKCU}\SOFTWARE\WOW6432Node` | redirected key |
    | `{HKLM\|HKCU}\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\{Shell Folders\|User Shell Folders}` | user shell folders (`shell:<ValueName>`)
    | `HKCR\` | `{HKLM,HKCU}\Software\Classes` |
    | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` | IFEO controls binary executive behavior |

### Autorun
- Overall
    - 🟦 Autoruns (SysinternalsSuite)
- Startup
    - 🟦 `RUN$ shell:Startup`  
      🟦 `RUN$ shell:Common Startup`
    - 🟦 `{HKLM|HKCU}\Software[\WOW6432Node]\Microsoft\Windows\CurrentVersion\Run\`  
      🟦 `{HKLM|HKCU}\Software[\WOW6432Node]\Microsoft\Windows\CurrentVersion\RunOnce\`  
      🟦 `{HKLM|HKCU}\Software[\WOW6432Node]\Microsoft\Windows\CurrentVersion\RunOnceEx\`  

          > Can be triggered by `CMD$ RunOnce.exe /explorer`.

    - 🟦 `{HKLM|HKCU}\Software[\WOW6432Node]\Microsoft\Windows NT\CurrentVersion\Winlogon\`  
      🟦 `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\`  
    - 🐧 `/etc/profile`
- Service
    - 🟦 `HKLM\SYSTEM\CurrentControlSet\Services\`  
      🟦 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\`
- Scheduled Task
    - 🟦 `CMD$ taskschd.msc`  
      🟦 `$ schtasks /query /FO list /V`  
    - 🟦 `%SystemRoot%\{System32|SysWOW64}\Tasks\`  
      🟦 `%SystemRoot%\Tasks\`  
    - 🟦 `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\`  
      🟦 `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\`
    - 🐧 `/etc/crontab`  
      🐧 `/etc/cron.d/`

- GPO

### Process
- Process List
    - `$ tasklist`
    - `$ wmic process`
    - `$ Get-CimInstance -ClassName Win32_Process`
- Advanced Tool
    - Process Monitor (SysinternalsSuite)
    - Process Explorer (SysinternalsSuite)
    - Task Explorer (ExplorerSuite)
    - Driver List (ExplorerSuite)
    - WinObj (SysinternalsSuite)
    - pspy

### Network
- Wireshark
- FakeNet-NG

### Memory
- Dumpit
- Volatility Workbench

### Logs

#### Windows Event
- Event Log File
    - `%SystemRoot%\System32\winevt\Logs\`
- Event List

    ```powershell
    PS# Get-WinEvent -ListProvider * -Erroraction Silentlycontinue | Select ProviderName -ExpandProperty Events | Select * -ExpandProperty LogLink | Format-Table LogName,ProviderName,Version,ID,Description
    ```

- Event Filter

    ```powershell
    Get-EventLog
    ```

    ```powershell
    Get-WinEvent -Path C:\Windows\System32\Winevt\Logs\System.evtx
    Get-WinEvent -ListLog *
    Get-WinEvent -ListLog System | Format-List -Property *
    (Get-WinEvent -ListLog *).ProviderNames
    (Get-WinEvent -ListProvider *).Events | Format-Table Id, Description
    ```

- Channel
    - Sysmon

        > [SysmonSimulator](https://rootdse.org/posts/understanding-sysmon-events/)

#### Syslog
