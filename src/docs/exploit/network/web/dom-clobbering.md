# DOM Clobbering
- Inject HTML into a page to manipulate the DOM to change the behavior of JavaScript on the page
    - Access by `id` directly or by `windows.id`

        ```html
        <any id="a"></any>
        <script>
            console.log(a)
            console.log(window.a)
        </script>
        ```

    - Access by `document.a` additionally

        ```html
        <img name="a">
        <form name="b"></form>
        <embed name="c">
        <object name="d"></object>
        <script>
            console.log(document.a)
            console.log(document.b)
            console.log(document.c)
            console.log(document.d)
        </script>
        ```

    - Access by combination of `id` and `name`

        ```html
        <any id="a"></any>
        <any id="a" name="b"></any>
        <script>
            console.log(a) // HTMLCollection[]
            console.log(a.a)
            console.log(a.b)
        </script>
        ```

    - Access multi-layer windows object

        ```html
        <iframe name="a" srcdoc='
            <iframe name="b" srcdoc="
                <iframe name=&amp;quot;c&amp;quot; srcdoc=&amp;quot;
                    <a id=d></a>
                &amp;quot;></iframe>
            "></iframe>
        '></iframe>
        <script>
            console.log(a.b.c.d)
        </script>
        ```

- Case Study
    - [XSS in GMail’s AMP4Email via DOM Clobbering](https://research.securitum.com/xss-in-amp4email-dom-clobbering/)
