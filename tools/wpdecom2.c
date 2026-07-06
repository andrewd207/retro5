/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* wpdecom2 - modern reimplementation of Corel WordPerfect's wpdecom.
 *
 * Format (reverse-engineered from linux/ins/wpdecom, FUN_08048990 via Ghidra):
 *   16-byte header starting with magic 0xFF 'W' 'P' 'C', then a canonical
 *   Okumura LZSS stream:
 *     - 4096-byte ring buffer, pre-filled with ' ' (0x20), start pos N-F = 0xFEE
 *     - flag byte per 8 tokens; bit==1 -> literal, bit==0 -> match
 *     - match = 2 bytes: offset = b1 | ((b2 & 0xF0) << 4)  (12-bit)
 *                        length = (b2 & 0x0F) + 3          (3..18)
 *   Decodes until input EOF.
 *
 * Exit codes match the original enough for install.wp's decomp():
 *   0 = decompressed ok, 2 = input not compressed (caller should just cp).
 */
#include <stdio.h>
#include <string.h>

#define N 4096
#define F 18
#define THRESHOLD 2

static unsigned char win[N];

int main(int argc, char **argv) {
    const char *inp = NULL, *outp = NULL;
    /* accept optional -s flag like the original: wpdecom [-s] infile outfile */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        if (!inp) inp = argv[i];
        else if (!outp) outp = argv[i];
    }
    if (!inp || !outp) { fprintf(stderr, "Usage: wpdecom [-s] infile outfile\n"); return 1; }

    FILE *in = fopen(inp, "rb");
    if (!in) { fprintf(stderr, "Couldn't open the file: %s\n", inp); return 1; }

    unsigned char hdr[16];
    if (fread(hdr, 1, 16, in) != 16 ||
        !(hdr[0] == 0xFF && hdr[1] == 'W' && hdr[2] == 'P' && hdr[3] == 'C')) {
        fclose(in);
        return 2;                       /* not a WP compressed file */
    }

    FILE *out = fopen(outp, "wb");
    if (!out) { fprintf(stderr, "Couldn't open the file: %s\n", outp); fclose(in); return 1; }

    memset(win, ' ', N);
    int r = N - F;                      /* 0xFEE */
    unsigned int flags = 0;
    int c;
    for (;;) {
        flags >>= 1;
        if ((flags & 0x100) == 0) {     /* out of flag bits: reload */
            if ((c = getc(in)) == EOF) break;
            flags = 0xFF00 | (c & 0xFF); /* high byte = 8-token counter */
        }
        if (flags & 1) {                /* literal */
            if ((c = getc(in)) == EOF) break;
            putc(c, out);
            win[r] = (unsigned char)c;
            r = (r + 1) & (N - 1);
        } else {                        /* back-reference */
            int b1 = getc(in); if (b1 == EOF) break;
            int b2 = getc(in); if (b2 == EOF) break;
            int pos = b1 | ((b2 & 0xF0) << 4);
            int len = (b2 & 0x0F) + THRESHOLD + 1;
            for (int k = 0; k < len; k++) {
                unsigned char b = win[(pos + k) & (N - 1)];
                putc(b, out);
                win[r] = b;
                r = (r + 1) & (N - 1);
            }
        }
    }
    fclose(out);
    fclose(in);
    return 0;
}
