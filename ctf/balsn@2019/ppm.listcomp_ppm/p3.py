#!/usr/bin/env python3

[[t.insert(i, t[p]+1) or t.pop(i+1) for i, p in enumerate(map(int,input().split()))] and print(max(t) - 1) for n, t in [[int(input()), [0]*10010]]]
