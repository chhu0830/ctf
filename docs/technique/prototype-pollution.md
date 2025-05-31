# Prototype Pollution
- `a = new A()`
  - `a`.  \_\_proto\_\_ === `A`.prototype
- `undefined` may be replaced when its prototype has the attribute.
- Trigger
  - Set
    - [lodash](https://snyk.io/vuln/SNYK-JS-LODASH-608086) (\_.setWidth, \_.set)
  - Merge / Extend
    - CVE-2019-11358 (jQuery $.extend)
  - Clone
- Prototype Chain
  > When finding a property, JavaScript will go through the Prototype
    Chain until \_\_proto\_\_ is null.

  ```javascript
  > a = []
  > b = []
  > a["__proto__"]["test"] = "testtest" // a["__proto__"] is array
  > b.test
  < "testtest"
  ```
- Case Study
  - [MITRE](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=prototype+pollution)
  - [HackerOne XSS](https://hackerone.com/reports/986386)
  - [CVE-2019-7609](https://slides.com/securitymb/prototype-pollution-in-kibana)
  - [Client-Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution)
  - [Exploiting Client-Side Prototype Pollution in the wild](https://blog.s1r1us.ninja/research/PP)
