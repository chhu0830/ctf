from pwn import *
import subprocess32 as subprocess

while True:
    r = remote('easiest.balsnctf.com', 9487)

    r.recvuntil('prefix = "')
    prefix = r.recvuntil('"')[:-1]
    print('Prefix: ' + prefix)

    try:
        pow_ans = subprocess.check_output('python pow.py {} 23'.format(prefix), shell=True, timeout=6).strip()
        print('Answer for PoW: ' + pow_ans)

        r.recvuntil("input:\n")
        r.sendline(pow_ans)

        r.interactive()
    except Exception as e:
        print(e)
        r.close()
