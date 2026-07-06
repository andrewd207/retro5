# The WordPerfect 8 for Linux registration-number scheme

*Technical / historical documentation. This is a description of how the
installer's registration check worked, reconstructed from the shipped
verifier. It is **not** a key generator, and no generator is included in this
repository. Running WordPerfect still requires a license you are entitled to
use.*

## Where the check lives

The installer script `install.wp` gated installation on the exit code of a
small, **non-stripped** helper binary, `veruxkey`, invoked as:

```
veruxkey -r LW8XR-<number>
```

Because the helper was not stripped, its verification routine
(`VerifyCorelUnixRegNum`, with a helper it calls `AndrewizeKey`) can be read
directly in a decompiler. No cryptography is involved — it is a self-check on
the digits of the number.

## Structure of a number

A registration number is the fixed prefix `LW8XR-` followed by a **10-character
payload**. (At the installer's prompt the user types only the 10-character
payload; the `LW8XR-` prefix is supplied by the installer.)

Conceptually the payload decodes to ten digits `p0 p1 … p9`, split into three
fields:

| positions   | meaning                                             |
|-------------|-----------------------------------------------------|
| `p0 p1 p2`  | a three-digit number **A**                          |
| `p3 p4 p5`  | a three-digit number **B**                          |
| `p6 p7 p8 p9` | a four-digit **checksum**                         |

## The two validation rules

1. **Product-prefix checksum.** Let `A` be the number formed by the first three
   digits and `B` the number formed by the next three. The last four digits
   must equal the **first four digits of the product `A × B`**. (For the prefix
   to always have four digits, `A` and `B` are each at least 100, so
   `A × B ≥ 10000`.)

2. **Exactly one letter-encoded digit.** Any single digit in the payload may be
   written as a *letter* instead of a numeral, using this fixed substitution
   (the routine `AndrewizeKey` decodes the letter back to its digit):

   ```
   E=0  Z=1  X=2  Q=3  F=4  M=5  P=6  T=7  R=8  A=9
   ```

   The verifier requires that **exactly one** of the ten payload characters be
   such a letter. A payload written as ten bare numerals — with no letter — is
   rejected, as is one with more than one letter.

Any known-good example number satisfies both rules; for instance, a payload of
the form `AAABBBCCCC` where `CCCC` is the four-digit product-prefix, with a
single position rewritten as its check-letter, passes.

## Why it's documented here

This scheme is part of the software's runtime behavior that the installer in
this repository has to interoperate with, and it is of historical interest as a
period example of an offline "registration number" self-check. It is recorded
here as documentation only. This repository intentionally does **not** ship the
original `veruxkey` binary, nor any script that produces numbers.

`tools/verify-regnum.py` is a heavily-commented, **verify-only** companion to
this document: it reports whether a number you already have satisfies the two
rules above. It cannot generate numbers, and it does not remove your obligation
to hold a valid license.
