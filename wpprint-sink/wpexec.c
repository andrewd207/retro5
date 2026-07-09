/* wpexec.c — wpexc-style command runner. See wpexec.h.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include "wpproto.h"
#include "wpexec.h"

int wp_run(const char *file, char *const argv[],
           const char *feed, size_t feedlen,
           char *out, size_t *outcap) {
    int inpipe[2] = { -1, -1 }, outpipe[2] = { -1, -1 };
    if (feed && pipe(inpipe) < 0) return WP_ST_PIPE;
    if (pipe(outpipe) < 0) {                       /* child stdout -> us         */
        if (feed) { close(inpipe[0]); close(inpipe[1]); }
        return WP_ST_PIPE;
    }
    pid_t pid = fork();
    if (pid < 0) {
        if (feed) { close(inpipe[0]); close(inpipe[1]); }
        close(outpipe[0]); close(outpipe[1]);
        return WP_ST_FORK;
    }
    if (pid == 0) {                                /* --- child --- */
        if (feed) { dup2(inpipe[0], 0); close(inpipe[0]); close(inpipe[1]); }
        dup2(outpipe[1], 1);                       /* stdout -> pipe             */
        close(outpipe[0]); close(outpipe[1]);
        int dn = open("/dev/null", O_WRONLY);      /* stderr -> /dev/null (wpexc)*/
        if (dn >= 0) { dup2(dn, 2); close(dn); }
        execvp(file, argv);
        _exit(0x24);                               /* wpexc's exec-fail marker   */
    }
    /* --- parent --- */
    if (feed) {
        close(inpipe[0]);
        for (size_t off = 0; off < feedlen; ) {
            ssize_t w = write(inpipe[1], feed + off, feedlen - off);
            if (w < 0) { if (errno == EINTR) continue; break; }
            off += (size_t)w;
        }
        close(inpipe[1]);
    }
    close(outpipe[1]);
    size_t got = 0, cap = out ? *outcap : 0;
    for (;;) {
        char buf[4096];
        ssize_t r = read(outpipe[0], buf, sizeof buf);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) break;
        if (out && got < cap) {
            size_t take = (size_t)r < cap - got ? (size_t)r : cap - got;
            memcpy(out + got, buf, take); got += take;
        }
    }
    close(outpipe[0]);
    if (outcap) *outcap = got;

    void (*prev)(int) = signal(SIGCLD, SIG_DFL);   /* wpexc toggles SIGCLD       */
    int st = 0, w;
    do { w = waitpid(pid, &st, 0); } while (w < 0 && errno == EINTR);
    signal(SIGCLD, prev);
    return WIFEXITED(st) ? WEXITSTATUS(st) : WP_ST_FORK;
}
