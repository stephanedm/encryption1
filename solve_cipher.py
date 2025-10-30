#!/usr/bin python3


ct = "IZWCVL BZWCJTM XWWT BWG"
import string
alpha = string.ascii_uppercase
for s in range(26):
    trans = str.maketrans(alpha, alpha[s:]+alpha[:s])
    print(f"shift {s:2d} ->", ct.translate(trans))
