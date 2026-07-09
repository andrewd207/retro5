/* wpsink.c — a modern WordPerfect 8 (Linux) print sink.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * The receiving end of WP's print IPC: speak the RE'd text protocol
 * (docs/print-ipc-protocol.md, wpproto.h) toward WordPerfect, accept the job
 * body, and hand it to a modern spooler (CUPS `lp`/`lpr`) — no dependence on
 * the 1998 xwpdest/wpexc binaries.
 *
 * STATUS: protocol vocabulary + transport RE-confirmed; the exact job-body
 * framing and the e_device/e_form payload layout are being validated with
 * capture-print-traffic.sh (spots marked << CONFIRM (trace) >>).
 *
 * Build:  make          Test: make test  (or ./wpsink --selftest)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "wpproto.h"
#include "wpdest.h"

static int verbose = 0;
#define LOG(...) do { if (verbose) fprintf(stderr, "wpsink: " __VA_ARGS__); } while (0)

/* ---- the message loop -----------------------------------------------------
 * Handshake, then dispatch newline-terminated tokens. A job accumulates its
 * body (e_job..e_print/e_go); on e_print/e_go we spool it via `spool_cmd` (if
 * given) or a CUPS `lp` line built from the captured device/form (wpdest).
 *
 * << CONFIRM (trace) >>: whether the body is inline text lines or wpexc's
 * 4-byte-LE framed block, and how e_device/e_form carry their payload.
 */
static int run_session(int fd, const char *spool_cmd, wp_dest *dst) {
    char line[8192];
    char *job = NULL; size_t joblen = 0, jobcap = 0;
    int in_job = 0, rc = 0;

    wp_write_msg(fd, WP_HANDSHAKE);

    for (;;) {
        ssize_t n = wp_read_line(fd, line, sizeof line);
        if (n < 0) { rc = 1; break; }
        if (n == 0) break;
        LOG("<- %s\n", line);

        if (!strcmp(line, WP_HANDSHAKE)) {
            continue;
        } else if (!strcmp(line, WP_JOB)) {
            in_job = 1; joblen = 0;
            wp_write_msg(fd, WP_STARTED);
        } else if (!strcmp(line, WP_DEVICE)) {
            /* << CONFIRM (trace) >>: device name payload -> dst->device */
            continue;
        } else if (!strcmp(line, WP_FORM)) {
            /* << CONFIRM (trace) >>: form/paper payload -> dst->form */
            continue;
        } else if (!strcmp(line, WP_GO) || !strcmp(line, WP_PRINT)) {
            char cmd[512];
            const char *use = spool_cmd ? spool_cmd : wp_dest_command(dst, cmd, sizeof cmd);
            LOG("spool: %s (%zu bytes)\n", use, joblen);
            int st = wp_spool(use, job, joblen);
            wp_write_msg(fd, st == 0 ? WP_QUEUED : WP_ER_SPOOL);
            wp_write_msg(fd, st == 0 ? WP_DONE   : WP_ERROR);
            in_job = 0; joblen = 0;
        } else if (!strcmp(line, WP_STOP)) {
            break;
        } else if (in_job) {
            if (joblen + (size_t)n + 1 > jobcap) {
                jobcap = (jobcap ? jobcap * 2 : 65536) + n + 1;
                char *nb = realloc(job, jobcap);
                if (!nb) { rc = 1; break; }
                job = nb;
            }
            memcpy(job + joblen, line, n); joblen += n;
            job[joblen++] = '\n';
        }
    }
    free(job);
    return rc;
}

/* ---- transports ----------------------------------------------------------- */
static int open_fifo(const char *path) {
    if (mkfifo(path, 0600) < 0 && errno != EEXIST) {
        fprintf(stderr, "wpsink: mkfifo(%s): %s\n", path, strerror(errno));
        return -1;
    }
    int fd = open(path, O_RDWR);
    if (fd < 0) fprintf(stderr, "wpsink: open(%s): %s\n", path, strerror(errno));
    return fd;
}

static int connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un a; memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        fprintf(stderr, "wpsink: connect(%s): %s\n", path, strerror(errno));
        close(fd); return -1;
    }
    return fd;
}

/* ---- self-test ------------------------------------------------------------ */
static int selftest(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 2;
    const char *script[] = { WP_JOB, "%!PS-Adobe-3.0", "showpage", WP_DEVICE, WP_PRINT, WP_STOP };
    if (fork() == 0) {
        close(sv[0]);
        char l[128]; wp_read_line(sv[1], l, sizeof l);   /* eat handshake */
        for (unsigned i = 0; i < sizeof script / sizeof *script; i++) wp_write_msg(sv[1], script[i]);
        char got[128]; int ok = 0;
        while (wp_read_line(sv[1], got, sizeof got) > 0)
            if (!strcmp(got, WP_DONE)) { ok = 1; break; }
        _exit(ok ? 0 : 1);
    }
    close(sv[1]);
    run_session(sv[0], "cat >/tmp/wpsink-selftest.ps", NULL);
    close(sv[0]);
    int st = 0; wait(&st);
    int ok = (access("/tmp/wpsink-selftest.ps", F_OK) == 0);
    fprintf(stderr, "selftest: %s (spooled body -> /tmp/wpsink-selftest.ps)\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    const char *sock = NULL, *fifo = NULL, *spool_cmd = NULL;
    wp_dest dst = { .device = NULL, .form = NULL, .landscape = 0, .copies = 1 };
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--socket")    && i+1 < argc) sock = argv[++i];
        else if (!strcmp(argv[i], "--fifo")      && i+1 < argc) fifo = argv[++i];
        else if (!strcmp(argv[i], "--spool")     && i+1 < argc) spool_cmd = argv[++i];
        else if (!strcmp(argv[i], "--device")    && i+1 < argc) dst.device = argv[++i];
        else if (!strcmp(argv[i], "--form")      && i+1 < argc) dst.form = argv[++i];
        else if (!strcmp(argv[i], "--landscape")) dst.landscape = 1;
        else if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "--selftest")) return selftest();
        else { fprintf(stderr,
            "usage: %s (--socket PATH | --fifo PATH) [--spool CMD | --device P --form F --landscape] [-v]\n"
            "       %s --selftest\n"
            "  With no --spool, builds a CUPS `lp` line from --device/--form.\n", argv[0], argv[0]);
            return 2; }
    }
    /* No explicit destination? adopt the one `wpselect` recorded ($WPCOM/wpsink.dest). */
    static char destbuf[128];
    if (!spool_cmd && !dst.device) {
        char cfg[288], dir[256]; wp_rendezvous_dir(dir, sizeof dir);
        snprintf(cfg, sizeof cfg, "%s/wpsink.dest", dir);
        FILE *cf = fopen(cfg, "r");
        if (cf && fgets(destbuf, sizeof destbuf, cf)) {
            destbuf[strcspn(destbuf, "\n")] = 0;
            if (*destbuf) dst.device = destbuf;
        }
        if (cf) fclose(cf);
    }
    if (verbose) { char d[256]; wp_rendezvous_dir(d, sizeof d);
        LOG("rendezvous %s (env %s), prefix '%s'; device=%s\n",
            d, WP_RENDEZVOUS_ENV, WP_SOCK_PREFIX, dst.device ? dst.device : "(CUPS default)"); }
    int fd = sock ? connect_unix(sock) : fifo ? open_fifo(fifo) : -1;
    if (fd < 0) { if (!sock && !fifo) fprintf(stderr, "need --socket or --fifo\n"); return 1; }
    int rc = run_session(fd, spool_cmd, &dst);
    close(fd);
    return rc;
}
