#!/usr/bin/env python3

python3 - <<'PY'
ct = "ACKP JTWAAWU DQLMW OWLLMAA"
import string
alpha = string.ascii_uppercase
for s in range(26):
    trans = str.maketrans(alpha, alpha[s:]+alpha[:s])
    print(f"shift {s:2d} ->", ct.translate(trans))
PY
