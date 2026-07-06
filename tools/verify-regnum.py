#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""
verify-regnum.py — check whether a WordPerfect 8 for Linux registration number
satisfies the installer's built-in validity rules.

  ┌─────────────────────────────────────────────────────────────────────────┐
  │  THIS IS A *VERIFIER*, NOT A GENERATOR.                                  │
  │                                                                          │
  │  It only answers "would the installer's check accept this number?".     │
  │  It does not produce numbers, and it does not remove your obligation to  │
  │  hold a license you are entitled to use. It exists as executable         │
  │  documentation of a period offline "registration number" self-check —   │
  │  see docs/registration-key-scheme.md for the prose write-up.            │
  └─────────────────────────────────────────────────────────────────────────┘

Background
----------
The original installer (`install.wp`) gated installation on the exit code of a
small helper, `veruxkey`, run as `veruxkey -r LW8XR-<number>`. There is no
cryptography involved: the routine is a self-check on the *digits* of the
number. This file re-implements that check so you can tell, offline, whether a
number you already have is well-formed.

A number is the fixed prefix ``LW8XR-`` followed by a 10-character *payload*.
The payload decodes to ten digits  p0 p1 … p9  that must obey two rules:

  1. Product-prefix checksum.
     A = the 3-digit number p0 p1 p2
     B = the 3-digit number p3 p4 p5
     p6 p7 p8 p9 must equal the first four digits of the product A × B.

  2. Exactly one letter-encoded digit.
     Any *one* payload digit may be written as a letter instead of a numeral,
     using the fixed substitution below (this is what `veruxkey`'s helper
     decodes back to a digit). Exactly one payload character must be such a
     letter — zero letters, or two or more, is rejected.
"""

import sys

# The letter <-> digit substitution. The index of a letter in this string IS the
# digit it decodes to:  E=0  Z=1  X=2  Q=3  F=4  M=5  P=6  T=7  R=8  A=9
LETTERS = "EZXQFMPTRA"

PREFIX = "LW8XR-"          # the installer supplies this; the user types the payload
PAYLOAD_LEN = 10


def verify(number: str):
    """Return (ok: bool, reason: str) for a full number or a bare 10-char payload."""
    s = number.strip().upper()

    # Accept either the full "LW8XR-XXXXXXXXXX" or just the 10-char payload.
    if s.startswith(PREFIX):
        payload = s[len(PREFIX):]
    elif s.startswith("LW8XR"):            # tolerate a missing dash
        payload = s[len("LW8XR"):].lstrip("-")
    else:
        payload = s

    if len(payload) != PAYLOAD_LEN:
        return False, (f"payload must be {PAYLOAD_LEN} characters "
                       f"(got {len(payload)}: {payload!r})")

    # Decode the payload to ten digits, counting how many characters were written
    # as check-letters. A character is either a decimal digit (kept as-is) or one
    # of the ten letters in LETTERS (decoded to its index digit).
    digits = []
    letter_count = 0
    for i, ch in enumerate(payload):
        if ch.isdigit():
            digits.append(int(ch))
        elif ch in LETTERS:
            digits.append(LETTERS.index(ch))
            letter_count += 1
        else:
            return False, f"illegal character {ch!r} at position {i} " \
                          f"(allowed: digits 0-9 or a letter from {LETTERS})"

    # Rule 2: exactly one letter-encoded digit.
    if letter_count != 1:
        return False, (f"exactly one digit must be written as a check-letter; "
                       f"found {letter_count}")

    # Rule 1: the last four digits are the first four digits of A × B.
    A = digits[0] * 100 + digits[1] * 10 + digits[2]
    B = digits[3] * 100 + digits[4] * 10 + digits[5]
    checksum = "".join(str(d) for d in digits[6:10])
    product = str(A * B)
    if len(product) < 4:
        # only possible if A or B is very small; a valid number keeps A,B >= 100
        return False, (f"A={A} B={B}: product {product} has fewer than 4 digits, "
                       f"so it has no 4-digit prefix to check against")
    expected = product[:4]
    if checksum != expected:
        return False, (f"checksum mismatch: A={A} B={B}, A*B={product}, "
                       f"first four digits {expected} != trailing digits {checksum}")

    return True, f"valid (A={A}, B={B}, A*B={product}, prefix {expected} matches)"


def main(argv):
    args = argv[1:]
    if not args:
        # read numbers from stdin, one per line, when no args are given
        args = [ln for ln in sys.stdin.read().split() if ln]
    if not args:
        print(__doc__)
        print("usage: verify-regnum.py <number> [<number> ...]\n"
              "       echo <number> | verify-regnum.py")
        return 2

    any_invalid = False
    for num in args:
        ok, reason = verify(num)
        print(f"{'VALID  ' if ok else 'INVALID'}  {num:<20}  {reason}")
        any_invalid |= not ok
    return 0 if not any_invalid else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
