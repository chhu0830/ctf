# TJCTF 2020


## Writeup


### A First Step
`Miscellaneous` `5 pts` `tjctf{so0p3r_d0oper_5ecr3t}`

> Written by boomo
> 
> Every journey has to start somewhere -- this one starts here (probably).
> 
> The first flag is `tjctf{so0p3r_d0oper_5ecr3t}`. Submit it to get
> your first points!


### Discord
`Miscellaneous` `5 pts` `tjctf{we_love_wumpus}`

> Written by KyleForkBomb
> 
> Strife, conflict, friction, hostility, disagreement. Come chat with
> us! We'll be sending out announcements and other important
> information, and maybe even a flag!
> 
> Try `?flag` when you get here!


### Broken Button
`Web` `10 pts` `tjctf{wHa1_A_Gr8_1nsp3ct0r!}`

> Written by saisree
> 
> This [site](https://broken_button.tjctf.org/) is telling me all I need to do is click a button to find the flag! Is it really that easy?

There is an button on the page, but it can not be pressed.

We check the source code and find a hidden button link to
`find_the_flag!.html`.

Access `https://broken_button.tjctf.org/find_the_flag!.html` and get
the flag.


### Forwarding
`Reversing` `10 pts` `tjctf{just_g3tt1n9_st4rt3d}`

> Written by KyleForkBomb
> 
> It can't be that hard... right?
> 
> [forwarding](./Reversing.10.Forwarding/d9c4527bc1d5c58c1192f00f2e2ff68f84c345fd2522aeee63a0916897197a7a_forwarding)

We first check if the flag stored in plaintext by `$ strings forwarding
| grep tjctf` and we get the flag.


### Gym
`Reversing` `20 pts` `tjctf{w3iGht_l055_i5_d1ff1CuLt}`

> Written by agcdragon
> 
> Aneesh wants to acquire a summer bod for beach week, but time is running out. Can you help him [create a plan](./Reversing.20.Gym/bed9d7b7327958dab4d07b06772a032f3e97455e310956558579e8838762b5e2_gym) to attain his goal?
> 
> `nc p1.tjctf.org 8008`

Use `IDA` and we can easily find that:
* Option 1: -4
* Option 2: -1
* Option 3: -5
* Option 4: -3

The goal is to reduce the weight from 211 to 180.

We can do option3 * 5 and option4 * 2 to reach the goal.


### Tinder
`Binary` `25 pts` `tjctf{0v3rfl0w_0f_m4tch35}`

> Written by agcdragon
> 
> [Start swiping!](./Binary.25.Tinder/6efe89a92ae7aaf9a68cffe5840f55103ca121be9b8953e6736cf71409a57910_match)
> 
> `nc p1.tjctf.org 8002`

> [exp.py](./Binary.25.Tinder/exp.py)

The `input()` function has two parameters.

The first one indicate the address to store the input, the second one *
16 indicate the length of the input.

We can get the flag only if `match(rbp - 0xc)` is `0xc0d3d00d`.

The input of `bio` is 8 * 16 bytes.

We can use input of `bio(rbp - 0x80)` to overwrite `match(rbp - 0xc)`
to `0xc0d3d00d` to get the flag.


### Login
`web` `30 pts` `tjctf{horizons890898}`

> Written by saisree
> 
> Could you login into this very secure site? Best of luck!

> [login.js](./Web.30.Login/login.js)

We know that the page is an html by observate `Network` of Chrome.

The check must be done at frontend.

Then we find the checking javascript.

Just read the javascript code and know that `username` is `admin` and
`md5(password)` is `4312a7be33f09cc7ccd1d8a237265798`, which is
`horizons`.


### Sarah Palin Fanpage
`web` `35 pts` `tjctf{C4r1b0u_B4rb1e}`

> Written by jpes707
> 
> Are you a true fan of Alaska's most famous governor? Visit the Sarah Palin fanpage.

The `VIP area` is denied because we need to like all of
`top 10 moments`.

However, the like can only up to 5.

We think that the result may be stored in `cookies` and we find that
there is a cookie named `data`.

After `url decode` and `base64 decode`, we can read the data easily.

```json
{"1":false,"2":false,"3":false,"4":false,"5":false,"6":false,"7":false,"8":false,"9":false,"10":false,"10 --":true,"9'":true,"9 or True":true}
```

By modify all `false` into `true` and then `url encode` and `base64 encode`, we
can get access to the `VIP area` and get the key.


### Login Sequel
`web` `40 pts` `tjctf{W0w_wHa1_a_SqL1_exPeRt!}`

> Written by saisree
> 
> [Login](http://login_sequel.tjctf.org/) as admin you must. This time, the client is of no use :(. What to do?)

There is an hint in the comment of the page.

```python
def get_user(username, password):
    database = connect_database()
    cursor = database.cursor()
    try:
        cursor.execute('SELECT username, password FROM `userandpassword` WHERE username=\'%s\' AND password=\'%s\'' % (username, hashlib.md5(password.encode())))
    except:
        return render_template("failure.html")
    row = cursor.fetchone()
    database.commit()
    database.close()
    if row is None: return None
    return (row[0],row[1])
```

It is abvious that there is a sql injection vulnerability.

We find that `or` and `--%20` will be detected.

We find that we have the account, we just need to bypass the password
checking, so we input `admin'/*` and get the flag.


### Chord Encoder
`Reversing` `40 pts` `flag{zats_wot_1_call_a_meloD}`

> Written by boomo
> 
> I tried creating my own [chords](./Reversing.40.Chord_Encoder/67be5bd036a4be8323314d1da6ad2e673963f76634a62ec47d53fb07a04a3722_chords.txt), but my [encoded sheet music](./Reversing.40.Chord_Encoder/c29857b8d4d1b2dfe502b5053d73844a08358ae681b2af8de6829b765dc2c28e_notes.txt) is a little hard to read. Please play me my song!
> 
> [chord_encoder.py](./Reversing.40.Chord_Encoder/da36df431da358250884ff9765e8c0c5f054b845aff31b85e37229159176bb9f_chord_encoder.py)

> [sol.py](./Reversing.40.Chord_Encoder/sol.py)

Decode reversely or there may be multiple choice, lick `d` and `e` are
both start with `010`.


### Seashell
`Binary` `50 pts` `tjctf{she_s3lls_se4_sh3ll5}`

> Written by KyleForkBomb
> 
> I heard there's someone [selling shells](./Binary.50.Seashells/d46850d6dd80f2b1132c9fe908e53f71e1a0a2f712ba193c29056ba1797afb4b_seashells)? They seem to be out of stock though...
> 
> `nc p1.tjctf.org 8009`

> [exp.py](./Binary.50.Seashells/exp.py)

Because the `shell()` function will check whether the `rdi` is a
specific value, we need to build ROP chain to modify `rdi` to the
specific value.

It should be noted that on some systems (like ubuntu 18.04), the
`system()` must be called when the address is in the 8 byte alignment.

When we build the ROP chain, we need to align the address to 8 byte by
adding a `ret` instruction.


## Unsolved


### Circles
`Cryptography` `10 pts`

> Written by jpes707
> 
> Some typefaces are mysterious...
> 
> [Circles.png](./Cryptography.10.Circles/f5e809c4c49f2c7d607d77c99f07bbd8e9b46dfbe61779201f5b185ed6642de3_Circles.png)


### Ling Ling
`Forensics` `10 pts`

> Written by KyleForkBomb
> 
> Who made this meme? I made this meme! unless.....


### Weak Password
`web` `50 pts`

> Written by saisree
> 
> It seems your login bypass skills are now famous! One of my friends has given you a challenge: figure out his password on this [site](http://weak_password.tjctf.org/). He's told me that his username is admin, and that his password is made of up only lowercase letters. (Wrap the password with tjctf{...})


### Gamer W
`web` `60 pts`

> Written by boomo
> 
> Can you figure out how to [cheat](http://gamer_w.tjctf.org/) the system?
