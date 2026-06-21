# XSS
> [Cross-site scripting (XSS) cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)  
> xsser

- Type
    - Self-XSS
    - Reflected XSS
    - Stored XSS
- Mitigation
    - Filter
  
        | Pattern       | Bypass                                     |
        |:--------------|:-------------------------------------------|
        | [SPACE]on...= | `<svg<TAB>onload=alert(1)>`                |
        | [SPACE]on...= | `<svg\nonload=alert(2)>`                  |
        | [SPACE]on...= | `<svg/ onload=alert(3)>`                   |
        | javascript:   | `<a href="\x01javascript:alert(4)">X</a>`  |
        | javascript:   | `<a href="java\tscript:alert(5)">X</a>`    |
        | javascript:   | `<a href="java&Tab;script:alert(6)">X</a>` |
        | <script       | JSFuck                                     |
  
    - Escape (HTML Entity)
  
        | Symbol | Alternative |
        |:-------|:------------|
        | `<`    | `&lt;`      |
        | `>`    | `&gt;`      |
        | `"`    | `&quot;`    |

    - Content Security Policy (CSP)
        > [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

        - script-src
        - Nonce

    - trusted-types (Chrome)
    - HTTP response header
    - Define trusted resources
    - HttpOnly

- Bypass
    - `<base>`
        - Change base URL of all relative URL
    - Relative Path Overwrite (RPO)

- Case Study
    - [XS-Search abusing the Chrome XSS Auditor](https://www.youtube.com/watch?v=HcrQy0C-hEA)
    - [Mutation XSS in Google Search](https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/)
    - [Breaking XSS mitigations via Script Gadgets](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf)
