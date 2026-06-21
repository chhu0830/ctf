# Discovery

## DNS
- dnsenum

    ```bash
    # dnsenum
    #   [--noreverse]
    #   [--recursion]
    #   <domain>

    dnsenum google.com
    ```

- gobuster

    ```bash
    # gobuster vhost
    #   [-H, --headers="<key>:<value>" ...]
    #   [--exclude-length={ <length> | <length>-<length> },...]
    #   [--append-domain]
    #   --domain=<domain>
    #   -w, --wordlist=<wordlist>
    #   -u, --url=<url>

    gobuster vhost --exclude-length=100,200-300 --append-domain --domain=${domain:?} --wordlist=/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --url=http://${domain:?}
    ```

- `knockpy.py`


### DNS Lookup
- dig

    ```bash
    # dig
    #   [@<server>]
    #   { <name> | -x <addr> } ...
    #   [ A | MX | NS | TXT | CNAME | <type> ]
    #   [{ +trace | +https | +nssearch | +<option> } ...]

    dig @8.8.8.8 www.google.com A
    dig www.google.com A +trace
    dig google.com +nssearch

    dig -x 8.8.8.8
    ```

- nslookup

    ```bash
    # nslookup
    #   [{
    #       -type={ A | <type> }
    #       -<option>[=<value>]
    #   } ...]
    #   { <name> | <addr> }
    #   [<server>]

    nslookup -type=A www.google.com 8.8.8.8

    nslookup 8.8.8.8
    ```

- drill

    ```bash
    # drill
    #   [-T]        (enable trace)
    #   {
    #       <name>
    #       -x <addr>
    #               (rDNS)
    #   }
    #   [@<server>] (specify DNS server)
    #   [ A | <type> ]

    drill www.google.com @8.8.8.8 A
    drill -T www.google.com          # trace

    drill -x 8.8.8.8
    ```

## Port
- `/dev/tcp/<HOST>/<PORT>`
- nc / ncat / socat
- Nmap

    ```bash
    # nmap
    #   [-v]        (verbose)
    #   [-n]        (disable DNS resolution)
    #   [-T{0..5}]  (5 is fastest)
    #   [-A]        (same as -O -sV -sC --traceroute)
    #   [-O]        (enable OS detection)
    #   [-Pn]       (skip host discovery)
    #   [-sn]       (disable port scan)
    #   [-sV]       (show service version info)
    #   [-sS]       (TCP SYN, default)
    #   [-sU]       (UDP scan)
    #   [-sC]       (same as --script=default)
    #   [--script={ "http-*" | default | vuln | * | <pattern> },...]
    #   [--script-trace]
    #               (show all data sent and received)
    #   [--script-help <pattern>]
    #               (/usr/share/nmap/scripts)
    #   [
    #       -p-         (all ports)
    #       -p{[ T: | U: ]{ <port> | <port>-<port> },...},...
    #       --top-ports <n>
    #   ]
    #   { <hostname> | <ip> | <range> | <subnet> }

    # Scan with default setting.
    nmap -A ${host:?}

    # Scan HTTP service.
    nmap --script="http-*" -p80 ${host:?}

    # Scan all TCP ports.
    nmap -v -n -T5 -sS -p- ${host:?}

    # Scan ports with version info.
    nmap -v -n -sV -p22,80,443 ${host:?}
    ```

## Service

### HTTP
- `$ certutil.exe -urlcache -f <url> <filename>`
- [HTTPie](https://devhints.io/httpie)
- dirsearch

    ```bash
    # dirsearch
    #   [-m, --http-method=<method>]
    #   [-H, --header="<name>: <value>" ...]
    #   [--cookie="<name>=<value>;..."]
    #   [-e, --extensions={<extension>|php|asp},...]
    #               (only replaces %EXT% by default)
    #   [-f, --force-extensions]
    #   [--prefixes=<prefix>,...]
    #   [--suffixes=<suffix>,...]
    #   [-r, --recursive]
    #   [--crawl]
    #   [-i, --include-status={<code>|<code>-<code>},...]
    #   [-x, --exclude-status={<code>|<code>-<code>},...]
    #   [--exclude-text=<text> ...]
    #   [--exclude-regex=<regex> ...]
    #   [--exclude-redirect=<redirect url> ...]
    #   -u, --url=<url>

    dirsearch -r -u ${url:?}
    ```

- gobuster

    ```bash
    # gobuster dir

    gobuster dir --url ${url:?} --wordlist ${wordlist:-/usr/share/wordlists/dirb/common.txt} -t ${threads:-100}
    ```

- dirb

    ```bash
    # dirb
    #   [-H <header_string>]
    #   [-c <cookie_string]
    #   [-X {<extension>|.html}]
    #   [-N <status_code>]
    #               (ignore responses with this code)
    #   <url>
    #   [<wordlist>,...]

    dirb ${url:?} ${wordlist}
    ```

- dirbuster

    ```bash
    # dirbuster
    ```

- feroxbuster
- wfuzz

    ```bash
    wfuzz -c -z file,${wordlist:-/usr/share/wordlists/dirb/common.txt} -hc ${hidecode:-404} ${url:?}/FUZZ

    #Hide all results with same line count to the result queried by parameter <baseArg1> and <baseArg2>.
    wfuzz -c -z file,${wordlist:?} -hl ${hideline:-BBB} ${url:?}/?FUZZ{<baseArg1>}=,FUZ2Z{<baseArg2>}=
    ```

- ffuf

### Git
- git-dumper

### LDAP
- ldapsearch

    ```bash
    ldapsearch -x -H ldap://${host:?} -b "" -s base "(objectClass=*)"
    ```

- ldapdomaindump

### Kerberos

### SMB
- smbclient

    ```bash
    # smbclient
    #   [--user=<user>]
    #   [--password=<password>]
    #   {
    #      -L \\<host>
    #               (list all)
    #      \\<host>\<path>
    #   }

    smbclient -L '\\'${host:?}
    ```

- enum4linux
- smbmap

    ```bash
    # smbmap
    #   [-u <username>]
    #   [-p <password>]
    #   { -H <host> | --host-file <file> }

    smbmap -u ${user:?} -p ${pass:?} -H ${host:?}
    ```

### SNMP
- snmpwalk

    ```
    snmpwalk -v2c -c public <site>
    ```

### WinRM
- evil-winrm
- impacket

### Telnet
- telnet
