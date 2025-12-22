# Network
> [WEB CTF CheatSheet](https://github.com/w181496/Web-CTF-Cheatsheet/blob/master/README.md#%E7%A9%BA%E7%99%BD%E7%B9%9E%E9%81%8E)  
> [Web Security CheatSheet](https://blog.p6.is/Web-Security-CheatSheet/)  
> [Basic Concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q#/)  
> [Awesome Web Security](https://github.com/qazbnm456/awesome-web-security)  
> [Basic concept of Penetration Testing](https://hackmd.io/@boik/ryf5wZM5Q?type=slide#/)  
> [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/index.html)  
> [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/stable/)  
> [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## HTTP Protocol
- [Basics of HTTP](https://developer.mozilla.org/zh-TW/docs/Web/HTTP/Basics_of_HTTP)
    - MIME

        > type/subtype;parameter=value

- [URI schemes](https://en.wikipedia.org/wiki/List_of_URI_schemes)
    - Data URI

        > data:[&lt;mediatype&gt;][;base64],&lt;data&gt;

## The Onion Routing Protocol (Tor)
> Tor is an overlay network.
> 
> It is composed by thousands (~ 6-11k) **relays**, connected through
> **channels** that form **circuits** inside which **cells** are sent
> and received.
>
> -- <cite>[microlab.red](https://microlab.red/2024/09/03/tor-internals-for-those-of-us-who-also-have-a-life-1-n/)</cite>

> [The Tor Project](https://www.torproject.org/)  
> [TOR internals, for those of us who also have a life (1/n) | microlab.red](https://microlab.red/2024/09/03/tor-internals-for-those-of-us-who-also-have-a-life-1-n/)  
> [TOR internals, for those of us who also have a life (2/n) | microlab.red](https://microlab.red/2024/09/23/tor-internals-for-those-of-us-who-also-have-a-life-2-n/)  
> [Creating a Testing Tor Network From Scratch | dax](https://medium.com/@dax_dev/creating-a-testing-tor-network-from-scratch-e952d76a18cb)  
> [Decentralized Routing in Tor Hidden Services](https://medium.com/@kyodo-tech/decentralized-routing-in-tor-hidden-services-40e0bc0793d5)

- Directory Authority

    > They are a set of specialized servers within the Tor network that
    > collectively generate and distribute a signed document (known as
    > the **consensus**) containing information about all known Tor relays.
    >
    > -- <cite>[The Tor Proejct](https://community.torproject.org/relay/governance/policies-and-proposals/directory-authority/)</cite>

    - [DA List](https://gitlab.torproject.org/tpo/core/tor/-/blob/HEAD/src/app/config/auth_dirs.inc)
    - Consensus
        - `$ curl https://collector.torproject.org/recent/relay-descriptors/consensuses/`

- Tor Circuit

    > Tor User → Guard Relay / Bridge Relay → Middle Relay → Exit Relay → Destination (example[.]com)
    >
    > -- <cite>[The Tor Project](https://community.torproject.org/relay/types-of-relays/)</cite>

    - Bridge Relay
        - not listed in the public Tor directory
        - use pluggable transports to obfuscate their traffic to make it harder to detect
    - Guard Relay
        - first relay (hop) in a Tor circuit
        - stable and fast
    - Middle Relay
        - concealment
    - Exit Relay
        - Exit Policy

- Onion Hidden Service (.onion)

    ```mermaid
    sequenceDiagram
        actor Client
        participant RP as Rendezvous Point
        participant SD as Hidden Service Directory
        participant IP as Introduction Point
        participant OS as Onion Service

        OS->>IP: estabilish long-term circuit
        activate IP
        OS->>SD: publish service descriptor (introduction point)
        Client->>RP: choose a relay
        activate RP
        Client->>SD: request service descriptor
        Client->>IP: request service (rendezvous point)
        IP->>OS: pass the request
        deactivate IP
        OS->>RP: meet the client
        deactivate RP
    ```

    - Onion Service
        - Period

            ```
            period_number = floor(unix_timestamp / period_length)
            period_length = 1440 min [default 1 day]
            ```

        - Identity Key

            > A 32 bytes ed25519 master key pair.

            ```
            identity_pubkey
            identity_prikey
            ```

        - Blinded Key

            > A daily-rotated identifier derived from **identity_pubkey**
            > related to the **period_number** and **period_length**.

            ```
            blinded_pubkey
            blinded_prikey
            ```

        - Descriptor Key

            > A key pair signed by **blinded_prikey** that is used to sign
            > the service descriptors.

        - Credential & Subcredential

            ```
            CREDENTIAL    = SHA3_256("credential" | identity_pubkey)
            SUBCREDENTIAL = SHA3_256("subcredential" | CREDENTIAL | blinded_pubkey)
            ```

        - Service Address (v3)

            > A 56 bytes long base32 encoded string with ".onion" suffix.

            ```
            service_address = base32(identity_pubkey | CHECKSUM | VERSION) + ".onion"
            CHECKSUM        = blake2b(".onion checksum" | identity_pubkey | VERSION)[:2]
            VERSION         = "\x03"
            ```

    - Hidden Service Directory (HSDir)

        > A subset of Tor relays that store **service descriptors**.

        - Descriptor ID

            > One can determine the HDDir that stores the **service_descripter**
            > from the **identity_pubkey** (embeded in the **service_address**) and the timestamp.
            >
            > Distributed Hash Table (DHT) Model
            > - The first **hsdir_spread_store** relays with the **relay_id**
            >   greater than **descriptor_id** are the target HSDirs.
            > 
            > - Client choose the HSDir randomly from **hsdir_spread_fetch** relays
            >   start from the first match.

            ```
            hsdir_n_replicas    = an integer in range [1, 16] with default value 2.
            hsdir_spread_fetch  = an integer in range [1,128] with default value 3.
            hsdir_spread_store  = an integer in range [1,128] with default value 4.
            shared_random_value = a pre-shared value determined by directory authorities for each period.

            descriptor_id = SHA3-256("stored-at-idx" | blinded_pubkey | hsdir_n_replicas | period_length | period_number)
            relay_id      = SHA3-256("node-idx" | node_identity | shared_random_value | period_number | period_length)
            ```

        - Service Descriptor

            > A service descriptor contains the introduction points, as long
            > as the signature, which can be verified by the pubkey embedded
            > in the service address.
            >
            > [HS-DESC-ENCRYPTION-KEYS](https://spec.torproject.org/rend-spec/hsdesc-encrypt.html#HS-DESC-ENCRYPTION-KEYS)

            - descriptor-lifetime
            - descriptor-signing-key-cert

                > A certificate that is signed by the blinded key to ensure the integrity.

            - superencrypted

                > Data encrypted with a symmetric key derived from **blinded_pubkey**
                > and **SUBCREDENTIAL** to make sure the client knows the **service_address**.

                - auth-client

                  > Decrypt information for authenticated users if restricted
                  > discovery is enabled.

                - encrypted

                  > Data encrypted with a symmetric key derived from **blinded_pubkey**,
                  > **subcredentail**, and **descriptor_cookie** (if restricted
                  > discovery is enabled, leave blank otherwise)

                  - introduction-point

                    > Provide 3 relays by default.

            - signature

    - Introduction Point

        > An onion service establishes long-term circuits to 3 different
        > Tor relays, called introduction points, to conceal its location
        > from clients.
        >
        > A client selects one of these introduction points, as listed in
        > the service descriptor, to initiate communication with the
        > service.

    - Rendezvous Point
        - verify secret from both side


## DNS

| Type | Port | Note |
|------|------|------|
| DNS | 53/tcp,udp |
| mDNS | 5353/udp | multicast to `224.0.0.251` for `.local` domain only |
| LLMNR | 5355/udp | multicast to `224.0.0.252` |
| NetBIOS | 137/udp (NBNS) | broadcast / wins |
