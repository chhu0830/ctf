#!/usr/bin/env python3
import random, time
from randcrack import RandCrack


f = open('./output.2.txt', 'r')

num = list(map(int,f.readlines()[1:-1]))

print(num, len(num))

for i in range(0x1337 - 624):
    if i % 100 == 0:
        print(i)

    rc = RandCrack()
    for n in num[i:i+624]:
        rc.submit(n)

    if rc.predict_randrange(3133731337) == num[i+624]:
        print('==========', i, '===========')


"""
for i in range(624):
	rc.submit(random.getrandbits(32))
	# Could be filled with random.randint(0,4294967294) or random.randrange(0,4294967294)

print("Random  result: {}\nCracker result: {}"
            .format(random.randrange(0, 4294967295), rc.predict_randrange(0, 4294967295)))
"""
