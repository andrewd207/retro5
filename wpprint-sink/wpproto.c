/* wpproto.c — shared WordPerfect 8 print IPC I/O.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 * See wpproto.h / docs/print-ipc-protocol.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "wpproto.h"

void wp_rendezvous_dir(char *out, size_t n) {
    const char *d = getenv(WP_RENDEZVOUS_ENV);
    if (!d || !*d) d = getenv("SHTMP");
    if (!d || !*d) d = WP_RENDEZVOUS_DIR;
    snprintf(out, n, "%s", d);
}

ssize_t wp_read_line(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == 0) return i ? (ssize_t)i : 0;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (c == WP_MSG_TERM) break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return (ssize_t)i;
}

int wp_write_msg(int fd, const char *token) {
    char line[80];
    int n = snprintf(line, sizeof line, "%s%c", token, WP_MSG_TERM);
    return write(fd, line, n) == n ? 0 : -1;
}

int wp_spool(const char *cmd, const char *body, size_t nbytes) {
    FILE *p = popen(cmd, "w");
    if (!p) return -1;
    if (nbytes && fwrite(body, 1, nbytes, p) != nbytes) { pclose(p); return -1; }
    return pclose(p);
}
