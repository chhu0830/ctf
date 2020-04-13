# DawgCTF 2020


## Writeup

### Sanity Check
`Misc` `10 pts` `DawgCTF{fr33_fl@gs}`

> Welcome to DawgCTF 2020! Challenges will be released on a rolling schedule. All new releases will be announced in the Discord.
> 
> DawgCTF{fr33_fl@gs}
> 
> Author: trashcanna

### Socialize with Social Distance
`Misc` `10 pts` `DawgCTF{h3y_wh@ts_uP_h3ll0}`

> Join our Discord! https://discord.gg/BPgvnvX
> 
> Author: trashcanna

### The Lady is a Smuggler
`Web/Networking` `25 pts` `DawgCTF{ClearEdge_ElizebethSmith)}`

> Our mysterious lady is smuggling a bit of extra information.
> 
> https://clearedge.ctf.umbccd.io/
> 
> Author: ClearEdge

View source code and you can find the image src with flag.

### Tracking
`Web/Networking` `100 pts` `DawgCTF{ClearEdge_uni}`

> What's that pixel tracking?
> 
> https://clearedge.ctf.umbccd.io/
> 
> Author: ClearEdge

There is an 1px img has onclick attribute.

Execute the javascript code then get the flag.

### Free Wi-Fi Part 1
`Web/Networking` `50 pts` `DawgCTF{w3lc0m3_t0_d@wgs3c_!nt3rn@t!0n@l}` 

> People are getting online here, but the page doesn't seem to be implemented...I ran a pcap to see what I could find out.
> 
> http://freewifi.ctf.umbccd.io/
> 
> Authors: pleoxconfusa and freethepockets
> 
> [free-wifi.pcapng](https://umbccd.io/files/8a457a56c7d7d2dc5a881389835ababc/free-wifi.pcapng?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjozMX0.XpHjFg.FoeuTcqBEqEYiiMY0ix8aMEBgGs)

Follow the pcap,
    we can find two pages `/forgotpassword.html` and `/staff.html`.

You can find `flag` at the bottom of `/staff.html`.

### Ask Nicely
`Reversing` `50 pts` `DawgCTF{+h@nK_Y0U}`

> Remember your manners!
> 
> Author: Novetta
> 
> [asknicely](https://umbccd.io/files/fcdf76c0d7eef3271b59cfd5270f2844/asknicely?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjoyNn0.XpHkXQ.JHhnhWRyobEqQ6RHIp7qL5oTj5A)

Use `ida` to decompile and find that there is an function named `flag()`.

Reverse the `flag()` and get the `flag`.

### Put your thang down flip it and reverse it
`Reversing` `150 pts` `DawgCTF{.tIesreveRdnAtIpilF,nwoDgnihTyMtuP}`

> Ra-ta-ta-ta-ta-ta-ta-ta-ta-ta.
> 
> Authors: trashcanna and pleoxconfusa
> 
> [missyelliott](https://umbccd.io/files/86bca4c09ec11555b9bccc4e3e8b868f/missyelliott?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjo0Mn0.XpKSFA.YTdaEDD7dpxDoUckQfnZT1Pkv1Q)

There are three functions in `main()` related to the input.

The first function do `~` operation on each byte.

The second function reverse each byte and then reverse the input.

The third function compare the output of above function to specific bytes.

Reverse the operations above and get the correct input, which is flag.

### On Lockdown
`Pwn` `50 pts` `DawgCTF{s3ri0u$ly_st@y_h0m3}`

> Better than locked up I guess
> 
> nc ctf.umbccd.io 4500
> 
> Author: trashcanna
> 
> [onlockdown.c](https://umbccd.io/files/087c60c597d10f3d904824b633149be1/onlockdown.c?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjoyMX0.XpK3wQ.gAaCQduya1z0dasH-Z-qGACRZ5k)
> [onlockdown](https://umbccd.io/files/f2a5226156210eda3fca50f4f9ba2401/onlockdown?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjoyMn0.XpK3wQ.2GzC5qrZhlG7a_ZSNxDODzxjRPE)

Simple buffer overflow.

### bof to the top
`Pwn` `100 pts` `DawgCTF{wh@t_teAm?}`

> Anything it takes to climb the ladder of success
> 
> nc ctf.umbccd.io 4000
> 
> Author: trashcanna
> 
> [bof.c](https://umbccd.io/files/5498a9823088d824484655fddfa528e0/bof.c?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjo1M30.XpLayA.-evsxVfhcO6UqeOW4uwnKb6YkN8)
> [bof](https://umbccd.io/files/9d1248db6822816b663974b07907803c/bof?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjo1Nn0.XpLayA.OBsEFydNRUvtlrKsyulJJMVhgBg)

We can know the binary is an 32-bit executable by `$ file <binary>`.

The `audition()` is the target,
    and there are two conditions to be statisfied to get the flag.

By the calling convention, we have to set the parameters on the stack.

Don't forget the return address of the `audition()`
    when you generate the payload.

### Nash
`Pwn` `150` `DawgCTF{L1k3_H0W_gr3a+_R_sp@c3s_Th0uGh_0mg}`

> Welcome to Nash! It's a NoSpaceBash! All you have to do is display the flag. It's right there.
> 
> cat flag.txt
> 
> Oh yeah...you can't use any spaces... Good luck!
> 
> nc ctf.umbccd.io 4600
> 
> Author: BlueStar

Search `bypass space`.

One solution is `$ cat<flag.txt`


## Not Solved

### Free Wi-Fi Part 3
`Web/Networking` `200 pts`

> Let's steal someone's account.
> 
> http://freewifi.ctf.umbccd.io/
> 
> Authors: pleoxconfusa and freethepockets
> 
> [free-wifi.pcapng](https://umbccd.io/files/8a457a56c7d7d2dc5a881389835ababc/free-wifi.pcapng?token=eyJ1c2VyX2lkIjoxOTk1LCJ0ZWFtX2lkIjoxMDA5LCJmaWxlX2lkIjozMX0.XpHjFg.FoeuTcqBEqEYiiMY0ix8aMEBgGs)

Maybe related to JWT

### Nash2
`Pwn` `200 pts`

> It's nospacebash for real this time!
> 
> nc ctf.umbccd.io 5800
> 
> Author: BlueStar
