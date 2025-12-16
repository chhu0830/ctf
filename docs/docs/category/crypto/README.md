# Crypto
<!-- toc -->

## Tool

### Decrypt
- pyCryptodome
- Crypto.Util.number

    | Function | Comment         |
    |:---------|:----------------|
    | inverse  | modulus inverse |

- Sage
    - [sagemath](https://sagecell.sagemath.org/)
    - [CoCalc](https://cocalc.com/)

### Recover
- unt-wister

### Brute Force
- Password Cracker
    - hashcat
    - John the Ripper
- Login Cracker
    - hydra

        ```
        $ hydra -l <username> -P /usr/share/wordlists/nmap.lst <server> http-post-form "/login.php:username=^USER^&password=^PASS^&sub=Login:Invalid username or password"
        ```

- Word List
    - wordlists
    - seclists
    - crunch

### openssl
- Generate

    > [Generate cert chain](https://blog.davy.tw/posts/use-openssl-to-sign-intermediate-ca/)  
    > [SAN](https://medium.com/@antelle/how-to-generate-a-self-signed-ssl-certificate-for-an-ip-address-f0dd8dddf754)  
    > /etc/ssl/openssl.cnf

    - Self-signed Certificate (Root CA)

        ```bash
        #CA
        openssl genrsa -out ca.key 4096
        openssl req -new -out ca.csr -sha256 \
            -key ca.key -nodes \
            -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name"

        openssl ca -selfsign -keyfile ca.key -in ca.csr -outdir . -out ca.crt \
            -startdate 20211001000000Z -enddate 20311001000000Z -config <(cat <<-EOF
        [ ca ]
        default_ca                   = CA_default

        [ CA_default ]
        database                     = ./index.txt
        email_in_dn                  = no
        rand_serial                  = yes
        default_md                   = sha256
        default_days                 = 730
        policy                       = policy_any

        [ policy_any ]
        countryName                  = supplied
        stateOrProvinceName          = optional
        organizationName             = optional
        organizationalUnitName       = optional
        commonName                   = supplied
        emailAddress                 = optional

        EOF
        )

        #CA in one command
        openssl req -new -sha256 -x509 -days 3650 -out ca.crt \
            -newkey rsa:4096 -nodes -keyout ca.key \
            -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name" \
            -addext "subjectAltName=DNS:example.com"
        ```

    - Sign certificate

        ```bash
        #CSR
        openssl req -new -out intermediate.csr -sha256 \
            -newkey rsa:4096 -nodes -keyout intermediate.key \
            -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Common Name" \
            -config <(cat <<EOF
        [ req ]
        ...
        EOF
        )

        #CRT
        openssl x509 -req -out intermediate.crt -in intermediate.csr -days 7300 \
            -CA ca.crt -CAkey ca.key -CAserial ca.serial -CAcreateserial \
            -extensions x509v3_config -extfile <(cat <<EOF
        [ x509v3_config ]
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid:always,issuer
        basicConstraints = CA:true, pathlen:0
        EOF
        )
        ```

    - Sign CRL

        ```bash
        #CRL
        openssl ca -gencrl -keyfile ca.key --cert ca.crt -out crl.pem \
            -crlexts crl_ext --crldays 730 -revoke ${CRT_PATH} -config <(cat <<EOF
        [ ca ]
        default_ca                   = CA_default

        [ CA_default ]
        database                     = ./index.txt
        default_md                   = sha256

        [ crl_ext ]
        authorityKeyIdentifier       = keyid:always,issuer:always
        EOF
        )
        ```

    - Sign Binary

        ```bash
		set -e

		readonly dir=demoCA
		readonly revoke_server=${1:?revoke server}

		mkdir ${dir}
		touch ${dir}/index.txt
		openssl rand -hex 16 > ${dir}/serial
		openssl rand -hex 16 > ${dir}/crlnumber

		openssl req -new -out ca.csr -sha256 \
		  -newkey rsa:4096 -keyout ca.key -nodes \
		  -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Test CA"

		openssl req -new -out codesign.csr -sha256 \
		  -newkey rsa:4096 -keyout codesign.key -nodes \
		  -subj "/C=TW/ST=Taiwan/L=Hsinchu/O=Organization/OU=Organization Unit/CN=Test Code Signing"

		openssl ca -selfsign -cert ca.crt -keyfile ca.key -in ca.csr -outdir . -out ca.crt \
		  -startdate 20200101000000Z -enddate 20300101000000Z \
		  -extensions x509v3_config -extfile <(cat <<EOF
		[ x509v3_config  ]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid:always,issuer
		basicConstraints = critical,CA:true, pathlen:0
		crlDistributionPoints = URI:http://${revoke_server}/ca.crl
		EOF
		)

		openssl ca -cert ca.crt -keyfile ca.key -in codesign.csr -outdir . -out codesign.crt \
		  -startdate 20200101000000Z -enddate 20300101000000Z \
		  -extensions x509v3_config -extfile <(cat <<EOF
		[ x509v3_config  ]
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid:always,issuer
		basicConstraints = critical,CA:false, pathlen:0
		keyUsage = critical,digitalSignature
		extendedKeyUsage = codeSigning
		crlDistributionPoints = URI:http://${revoke_server}/ca.crl
		EOF
		)

		openssl pkcs12 -export -passout pass: -out codesign.pfx -inkey codesign.key -in codesign.crt -certfile ca.crt
        # openssl ca -revoke ${crt:?cert to revoke} -cert ca.crt -keyfile ca.key
		openssl ca -gencrl -cert ca.crt -keyfile ca.key -out ca.crl
        ```

        ```powershell
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import("C:\Users\user\Desktop\codesign.pfx", $null, "Exportable,PersistKeySet")
        Set-AuthenticodeSignature -FilePath "C:\Users\user\Desktop\xvrshell.exe" -Certificate $cert
        ```
    
- Verify
    - Cert Chain

        ```bash
        openssl verify -CAfile root.crt -untrusted intermediate.crt product.crt
        openssl verify -CAfile <(cat intermediate.crt root.crt) product.crt

        openssl verify -crl_check -CAfile <(cat ca.crt crl.pem) intermediate.crt
        ```

    - Cert Pair

        ```bash
        printf '123' \
            | openssl rsautl -encrypt -inkey <(openssl x509 -pubkey -noout -in sensor.crt) -pubin \
            | openssl rsautl -decrypt -inkey sensor.key
        ```

    - CRL

        ```bash
        openssl s_client \
            -CAfile <(cat ca.crt crl.pem) \
            -crl_check -connect 127.0.0.1:12345 \
        ```

- Read cert

    ```bash
    openssl x509 -in product.crt -noout -text
    ```

- TLS Server / Client
    - Basic

        ```bash
        openssl s_server -key server.key -cert server.crt [-accept <ip>:<port>]
        openssl s_client [-showcerts] -connect <ip>:<port>
        ```

    - Verify Server

        ```bash
        openssl s_server [-debug] \
            -CAfile root.crt \
            -cert_chain <(cat product.crt intermediate.crt) \
            -cert server.crt -key server.key \
            [-accept <ip>:<port>]

        openssl s_client [-showcerts] \
            -CAfile root.crt \
            -verify_return_error \
            -connect <ip>:<port>
        ```

    - Mutual Auth

        ```bash
        #Server Alternative 1
        openssl s_server [-debug] \
            -CAfile root.crt \
            -cert_chain <(cat product.crt intermediate.crt) \
            -cert server.crt -key server.key \
            -verify_return_error -Verify 5 \
            [-accept <ip>:<port>]

        #Server Alternative 2
        socat "OPENSSL-LISTEN:8888,cafile=root.crt,certificate=client-chain.crt,key=client.key,reuseaddr,verify" STDOUT

        #Client Alternative 1
        openssl s_client [-showcerts] \
            -CAfile root.crt \
            -cert_chain <(cat product.crt intermediate.crt) \
            -cert client.crt -key client.key \
            -verify_return_error \
            -connect <ip>:<port>

        #Client Alternative 2
        curl \
            --cacert root.crt \
            --cert <(cat client.crt product.crt intermediate.crt) \
            --key client.key \
            --resolve <Cert CN>:<port>:<ip>
            https://<Cert CN>:<port>

        ```

- S/MIME data signing

    ```bash
    $ openssl smime -sign -binary -signer cert.pem -inkey key.pem -outform DER -md sha256 -out sigature -in ${filename:?} -nocerts
    $ openssl smime -verify -in sig -inform DER -content ${filename:?} -noverify -out /dev/null
    ```
        
- MakeCert and New-SelfSignedcertificate

    ```powershell
    # MakeCert -n 'CN=code.signing' -ss My -r -pe -sr localmachine -cy end -eku 1.3.6.1.5.5.7.3.3 -len 4096 -b 2020/01/01 -e 2025/01/01
    New-SelfSignedCertificate -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 4096 -Type CodeSigningCert -KeyUsage DigitalSignature -KeyUsageProperty Sign -Subject 'CN=code signing test'
    Set-AuthenticodeSignature -FilePath @(Get-ChildItem -Recurse '*.exe','*.dll','*.ps1') -Certificate (Get-ChildItem Cert:\CurrentUser\My -codesigning)[0] -IncludeChain 'NotRoot' -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.globalsign.com/?signature=sha2'
    signtool.exe verify /pa <binary>
    ```

- Signed Certificate Timestamp (SCT)
    - [Signed Certificate Timestamp (SCT) Validation | Google](https://github.com/google/certificate-transparency/blob/master/docs/SCTValidation.md)


## Background

### Cryptanalysis
- Kerckhoff's Principle
- Classical Cryptanalysis
    - Mathmatical Analysis
    - Brute-Force Attacks
        - Substitution Cipher

            > Caesar Cipher

            - Exhaustive Key Search
            - Letter Frequency Analysis
- Implementation Attacks
- Social Engineering

### Symmetric Cipher
- Stream Cipher

    > encrypt bits individually
    > 
    > usually small and fast  
    > 
    > security dependes entirely on key stream (sync, async), which is random and reproducible
    
    - vulnerable to reused key attack

        ```
        E(A) = A xor C
        E(B) = B xor C
        E(A) xor E(B) = A xor B
        ```

    - key stream generator

        > the key stream generator works like a Pseudorandom Number Generator (RNG),
        > which generate sequences from initial seed (key) value
        > 
        > ![](<https://latex.codecogs.com/gif.latex?s_0 = seed, s_{i+1} = f(s_i, s_{i-1}, ..., s_{i-t})>)
    
        - Linear Congruential Generator (LCG)
        
            ![](<https://latex.codecogs.com/gif.latex?S_0 = seed, S_{i+1} = AS_i + B\ mod\ m>)  
        
            Assume

            - unknown A, B and S0 as key
            - m = 2^32
            - S1, S2, S3 are known  
        
            Solving  

            - ![](<https://latex.codecogs.com/gif.latex?S_2 = AS_1 + B\ (mod\ m)>)
            - ![](<https://latex.codecogs.com/gif.latex?S_3 = AS_2 + B\ (mod\ m)>)
        
            Answer

            - ![](<https://latex.codecogs.com/gif.latex?A = (S_2 - S_3) \times inverse(S_1 - S_2, m)\ (mod\ m)>)
            - ![](<https://latex.codecogs.com/gif.latex?B = (S_2 - AS_1)\ (mod\ m)>)
        
        - MT19937

            > python's default RNG

            - can be recovered by 32x624 consecutive bits
                - `from randcrack import RandCrack`

        - Lineare Feedback Shift Register (LFSR)

            ![](<https://latex.codecogs.com/gif.latex?S_{i+3} = S_{i+1} \oplus S_{i}>)
            
            - Characteristic Polynomial
                - ![](<https://latex.codecogs.com/gif.latex?P(x) = x^m + p_{m-1}x^{m-1} + ... + p_1x + p_0>)


- Block Cipher
    > - always encrypt a full block (several bits)
    > - common for internet applications
