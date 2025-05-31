# Deserialization
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
