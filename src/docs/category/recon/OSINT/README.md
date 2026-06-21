# OSINT

## Attack Surface
- [SHODAN](https://www.shodan.io/search/examples)

    > Search Engine for the Internet of Everything

    ```
    # Search Query
    #   <keyword> ...
    #   [{[-(filter out)]<attr>:<value>,...(or)} ...(and)]
    #     country:{<country>|tw|us}

    hostname:google.com,facebook.com
    http.html:"index of" country:tw
    Microsoft-IIS port:8530,8531 country:tw -http.status:403  # WSUS
    ```

- [Censys](https://search.censys.io/)

    > Censys helps organizations, individuals, and researchers find and monitor
    > every server on the Internet to reduce exposure and improve security

- [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

    ```
    # {keyword | "<full match>"}
    #   [-<exclusion>]
    #   [site:<domain>]
    #   [filetype:<ext>]
    #   [intitle:<title>]

    intitle:"index of" setting.php
    ```

- [OSINT Framework](https://osintframework.com/)
- maltego

    > A platform for open-source intelligence (OSINT) and cyber investigations

### Domain
- [crt.sh](https://crt.sh/)

    > Enter an Identity (Domain Name, Organization Name, etc)

- [robtex](https://www.robtex.com/)

    > Subdomains

- [dnsdumpster](https://dnsdumpster.com/)

    > dns recon & research, find & lookup dns records

- [IANA WHOIS Service](https://www.iana.org/whois)
- [DomainTools](https://whois.domaintools.com/)
- [VirusTotal](https://www.virustotal.com/gui/home/search)



## Tech Stack
- [Netcraft Site Report](https://sitereport.netcraft.com/)

    > Find out the infrastructure and technologies used by any site

- [Wappalyzer](https://www.wappalyzer.com/?utm_source=popup&utm_medium=extension&utm_campaign=wappalyzer)
