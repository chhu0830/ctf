# Persistent
- Startup
  - 🟦 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` (`$ shell:startup`)  
    🟦 `%SystemDrive%\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` (`$ shell:Common Startup`)
  - 🟦 `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\`  
    🟦 `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\`  
    🟦 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`  
    🟦 `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\`
  - 🐧 `/etc/profile`
- Service
  - 🟦 `HKLM\SYSTEM\CurrentControlSet\Services\`  
    🟦 `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\`
- Scheduled
  - 🟦 `$ taskschd.msc`  
    🟦 `$ schtasks /query /FO list /V`  
    🟦 `%SystemRoot%\System32\Tasks\`  
    🟦 `%SystemRoot%\Tasks\`  
    🟦 `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\`  
    🟦 `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\`
  - 🟦 GPO
  - 🐧 `/etc/crontab`  
    🐧 `/etc/cron.d/`

