/* test.c — printertocups smoke test.  ./p2c-test list            (enumerate; safe)
 *                                     ./p2c-test submit DEST FILE (spool FILE to DEST; prints!)
 * SPDX-License-Identifier: MIT */
#include "p2c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *cmd = argc > 1 ? argv[1] : "list";

    if (p2c_init() != 0) { fprintf(stderr, "p2c_init failed (libcups missing?)\n"); return 1; }

    if (!strcmp(cmd, "list")) {
        P2CPrinter p[64];
        int n = p2c_enum(p, 64), i;
        if (n < 0) { fprintf(stderr, "p2c_enum failed\n"); return 1; }
        printf("%d CUPS destination(s):\n", n);
        for (i = 0; i < n; i++)
            printf("  %-24s %s%s\n", p[i].name, p[i].is_default ? "[default] " : "", p[i].info);
        p2c_shutdown();
        return 0;
    }

    if (!strcmp(cmd, "submit") && argc >= 4) {
        FILE *f = fopen(argv[3], "rb"); long len; char *buf;
        if (!f) { perror("fopen"); return 1; }
        fseek(f, 0, SEEK_END); len = ftell(f); fseek(f, 0, SEEK_SET);
        buf = malloc(len); if (fread(buf, 1, len, f) != (size_t)len) { fclose(f); return 1; }
        fclose(f);
        long h = p2c_submit(argv[2], "p2c-test", P2C_POSTSCRIPT, buf, len, 0, 0);
        free(buf);
        printf("submitted job handle %ld to '%s'; waiting...\n", h, argv[2]);
        printf("drain: %s\n", p2c_wait_idle(15000) == 0 ? "done" : "TIMEOUT");
        p2c_shutdown();
        return h > 0 ? 0 : 1;
    }

    fprintf(stderr, "usage: %s list | submit DEST FILE.ps\n", argv[0]);
    return 2;
}
