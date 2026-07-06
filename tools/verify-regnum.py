#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""
verify-regnum.py — check a WordPerfect 8 for Linux registration number against
the rules its installer's `veruxkey` helper actually enforced.

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  THIS IS A *VERIFIER*, NOT A GENERATOR.                                  │
  │  It reports whether a number you already have would be accepted; it does │
  │  not produce numbers, and it does not remove your obligation to hold a   │
  │  license you are entitled to use. See docs/registration-key-scheme.md.   │
  └─────────────────────────────────────────────────────────────────────────┘

The check CHANGED between releases — reverse-engineered from the shipped
`veruxkey` binaries (run `veruxkey -r LW8XR-<number>`):

  * WordPerfect 8.0 (veruxkey 8.0.0076): the -r check is **format only** — the
    fixed prefix `LW8XR` (an optional dash) followed by exactly 10 characters of
    ANY content. There is no checksum: that binary imports only printf/exit — no
    atoi/sprintf/strncmp — so it cannot compute one. `LW8XR-!!!!!!!!!!` is
    accepted.

  * WordPerfect 8.1 (later veruxkey): the -r check was HARDENED. The 10-char
    payload decodes to ten digits p0..p9 that must satisfy BOTH:
      1. Product-prefix checksum: with A = p0p1p2 and B = p3p4p5, the last four
         digits p6p7p8p9 equal the first four digits of A × B.
      2. Exactly one payload digit is written as a letter from the fixed set
         E=0 Z=1 X=2 Q=3 F=4 M=5 P=6 T=7 R=8 A=9 (decoded back to its digit).

A number valid on 8.0 is therefore often rejected by 8.1. (The separate `-a`
"additional license key" scheme, prefix `LW8XW`, has its own real validation in
both releases and is NOT reversed here.)

Exit status: 0 if accepted by the strict (8.1) rule, 1 otherwise.
"""

import sys

LETTERS = "EZXQFMPTRA"    # index == decoded digit: E=0 Z=1 X=2 Q=3 F=4 ... A=9
PREFIX = "LW8XR"
PAYLOAD_LEN = 10


def _payload(number):
    """Extract the payload from 'LW8XR[-]<payload>' (or a bare payload)."""
    s = number.strip().upper()
    if s.startswith(PREFIX):
        s = s[len(PREFIX):]
        if s.startswith("-"):
            s = s[1:]
    return s


def verify_v80(number):
    """WordPerfect 8.0 (veruxkey 8.0.0076): prefix + length only, no checksum."""
    p = _payload(number)
    if len(p) != PAYLOAD_LEN:
        return False, f"payload is {len(p)} chars; 8.0 needs exactly {PAYLOAD_LEN}"
    return True, "accepted (8.0 checks only the LW8XR prefix + 10-char length)"


def verify_v81(number):
    """WordPerfect 8.1: prefix + length + A*B product-prefix checksum + exactly
    one letter-encoded digit."""
    p = _payload(number)
    if len(p) != PAYLOAD_LEN:
        return False, f"payload is {len(p)} chars; need {PAYLOAD_LEN}"

    digits = []
    letters = 0
    for i, ch in enumerate(p):
        if ch.isdigit():
            digits.append(int(ch))
        elif ch in LETTERS:
            digits.append(LETTERS.index(ch))
            letters += 1
        else:
            return False, f"illegal character {ch!r} at position {i}"

    if letters != 1:
        return False, f"exactly one digit must be a check-letter; found {letters}"

    A = digits[0] * 100 + digits[1] * 10 + digits[2]
    B = digits[3] * 100 + digits[4] * 10 + digits[5]
    checksum = "".join(str(d) for d in digits[6:10])
    product = str(A * B)
    if len(product) < 4:
        return False, f"A={A} B={B}: A*B={product} has no 4-digit prefix"
    if checksum != product[:4]:
        return False, (f"checksum mismatch: A={A} B={B}, A*B={product}, "
                       f"first four {product[:4]} != trailing {checksum}")
    return True, f"valid (A={A}, B={B}, A*B={product}, prefix {product[:4]} matches)"


def main(argv):
    args = argv[1:]
    if not args:
        args = [ln for ln in sys.stdin.read().split() if ln]
    if not args:
        print(__doc__)
        print("usage: verify-regnum.py <number> [<number> ...]")
        return 2

    worst = 0
    for num in args:
        ok80, why80 = verify_v80(num)
        ok81, why81 = verify_v81(num)
        print(f"{num}")
        print(f"  8.0: {'ACCEPT ' if ok80 else 'REJECT '} {why80}")
        print(f"  8.1: {'ACCEPT ' if ok81 else 'REJECT '} {why81}")
        if not ok81:
            worst = 1
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv))
