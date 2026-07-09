/* wpcups.c — enumerate CUPS destinations via lpstat. See wpcups.h.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wpcups.h"
#include "wpexec.h"

/* `lpstat -a` lines look like: "HP_LaserJet accepting requests since ..."
 * `lpstat -d` prints:          "system default destination: HP_LaserJet"
 * We parse the first whitespace-delimited token(s). */

int wp_cups_printers(char names[][WP_CUPS_NAMEMAX], int max) {
    char out[8192]; size_t cap = sizeof out - 1;
    char *const av[] = { "lpstat", "-a", NULL };
    int st = wp_run("lpstat", av, NULL, 0, out, &cap);
    if (st < 0) return -1;
    out[cap] = 0;
    int n = 0;
    for (char *line = strtok(out, "\n"); line && n < max; line = strtok(NULL, "\n")) {
        char *sp = strchr(line, ' ');
        size_t len = sp ? (size_t)(sp - line) : strlen(line);
        if (len == 0 || len >= WP_CUPS_NAMEMAX) continue;
        memcpy(names[n], line, len); names[n][len] = 0;
        n++;
    }
    return n;
}

int wp_cups_option(const char *printer, const char *keyword,
                   char choices[][WP_CUPS_NAMEMAX], int max, int *def) {
    if (def) *def = -1;
    char out[8192]; size_t cap = sizeof out - 1;
    char *const av[] = { "lpoptions", "-p", (char *)printer, "-l", NULL };
    if (wp_run("lpoptions", av, NULL, 0, out, &cap) < 0) return -1;
    out[cap] = 0;
    /* lines: "PageSize/Page Size: Custom.WxH *Letter A4 ..."  match by keyword */
    for (char *line = strtok(out, "\n"); line; line = strtok(NULL, "\n")) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        size_t klen = strlen(keyword);
        if (strncmp(line, keyword, klen) != 0 ||
            (line[klen] != '/' && line[klen] != ':')) continue;
        int n = 0;
        for (char *tok = strtok(colon + 1, " \t"); tok && n < max; tok = strtok(NULL, " \t")) {
            int isdef = (*tok == '*');
            if (isdef) tok++;
            if (!*tok || strncmp(tok, "Custom", 6) == 0) continue;   /* skip Custom.WxH */
            if (strlen(tok) >= WP_CUPS_NAMEMAX) continue;
            if (isdef && def) *def = n;
            snprintf(choices[n++], WP_CUPS_NAMEMAX, "%s", tok);
        }
        return n;
    }
    return -1;   /* option not offered by this printer */
}

int wp_cups_default(char *out, int n) {
    char buf[512]; size_t cap = sizeof buf - 1;
    char *const av[] = { "lpstat", "-d", NULL };
    if (wp_run("lpstat", av, NULL, 0, buf, &cap) < 0) return -1;
    buf[cap] = 0;
    /* take the last whitespace-delimited token on the line */
    char *p = strrchr(buf, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ') p++;
    char *e = p;
    while (*e && *e != '\n' && *e != ' ') e++;
    if (e == p) return -1;                     /* "no system default destination" */
    int len = (int)(e - p);
    if (len >= n) len = n - 1;
    memcpy(out, p, len); out[len] = 0;
    return 0;
}
