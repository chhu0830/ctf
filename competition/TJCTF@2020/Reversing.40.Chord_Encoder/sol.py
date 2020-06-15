#!/usr/bin/env python3

with open('./c29857b8d4d1b2dfe502b5053d73844a08358ae681b2af8de6829b765dc2c28e_notes.txt') as f:
    notes = f.readline().strip()[::-1]

with open('./67be5bd036a4be8323314d1da6ad2e673963f76634a62ec47d53fb07a04a3722_chords.txt') as f:
    chrods = {kv.split()[1][::-1]: kv.split()[0] for kv in f.read().split('\n')}

i = 0
r = []
while i < len(notes):
    for key in chrods:
        if notes[i:].find(key) == 0:
            i += len(key)
            r += chrods[key]
            break

s = ''.join([str(ord(c) - ord('A') + 1) if c.isupper() else c for c in r[::-1]])

print(bytes.fromhex(s).decode('utf-8'))
