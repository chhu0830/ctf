#!/usr/bin/env python3


# [[[ for v, c in input().split()] for _ in range(n)] for n, m in input().split()]

"""
n, m = map(int, input().split())

bag = [0]*(m+1)

for _ in range(n):
    v, c = map(int, input().split())
    for i in range(m-c+1):
        if bag[i+c] + v > bag[i]:
            bag[i] = bag[i+c] + v

print(bag[0])


[[0]*(m+1)[i+c]+v for i in range(m-c+1)]


[[] for n,m in [map(int,input().split())]]
"""
# [[[[b.pop(i) and b.insert(i,b[i+int(c)]+int(v)) for i in range(int(m)-int(c)+1) if b[i+int(c)]+int(v) > b[i]] for v, c in [input().split()]] for _ in range(int(n))] for n, m, b in [input().split() + [[0]*3000]]]
[[[[b.insert(i,b[i+c]+v)or b.pop(i+1)for i in range(int(m)-c+1)if b[i+c]+v>b[i]]for v,c in[map(int,input().split())]]for _ in range(int(n))]and print(b[0])for n,m,b in [input().split()+[[0]*3000]]]
