#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from chal import toHEX, getJapList
from pwn import *


print '\n'.join([disasm(jap) for jap in getJapList()])
