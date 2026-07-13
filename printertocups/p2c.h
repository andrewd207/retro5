/* p2c.h — printer-to-CUPS: WordPerfect's print backend, reimplemented against CUPS.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * A small shared library that replaces the interface WordPerfect uses to talk to its 1998 print
 * server (xwpdest/wpexc over the fragile startup-IPC FIFO). CUPS is the real print server, so jobs
 * go straight to it via libcups. The API is ASYNC and THREAD-SAFE: p2c_submit() copies the job and
 * returns immediately; a worker thread does the (potentially slow) CUPS submission off WP's UI thread.
 *
 * retro5 deep-loads this (dlopen RTLD_DEEPBIND), and this library in turn deep-loads libcups, so
 * CUPS's modern glibc/gnutls dependencies never collide with WP's libc5 shim.
 */
#ifndef PRINTERTOCUPS_H
#define PRINTERTOCUPS_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[128];        /* CUPS destination name (queue) */
    char info[128];        /* human description (printer-info), if any */
    int  is_default;       /* 1 if this is the CUPS default destination */
} P2CPrinter;

typedef struct {
    const char *name;      /* IPP/lp option name  (e.g. "media", "sides", "copies") */
    const char *value;     /* option value        (e.g. "A4", "two-sided-long-edge") */
} P2COpt;

/* Job body MIME types (pass to p2c_submit `format`). */
#define P2C_POSTSCRIPT "application/postscript"
#define P2C_PDF        "application/pdf"

/* Bring up libcups + the worker thread(s). Idempotent. Returns 0 on success, -1 if libcups is
 * unavailable (in which case p2c_submit/p2c_enum degrade to no-ops / 0). */
int  p2c_init(void);

/* Enumerate CUPS destinations into out[0..max-1]; returns the count written (>=0) or -1 on error.
 * Thread-safe. */
int  p2c_enum(P2CPrinter *out, int max);

/* Queue a print job (async, thread-safe). `dest` = CUPS queue name (NULL/"" = CUPS default);
 * `title` = job title; `format` = P2C_POSTSCRIPT or P2C_PDF; `data`/`len` = the job body (copied,
 * so the caller may free immediately); opts[0..nopt-1] = per-job options (names/values copied).
 * Returns a positive job handle, or -1 on error. Never blocks on the actual spooling. */
long p2c_submit(const char *dest, const char *title, const char *format,
                const void *data, size_t len, const P2COpt *opts, int nopt);

/* Block until the queue is drained (all submitted jobs handed to CUPS) or `timeout_ms` elapses
 * (<0 = wait forever). Returns 0 if drained, -1 on timeout. Mainly for tests / clean shutdown. */
int  p2c_wait_idle(int timeout_ms);

/* Stop the worker(s) and release resources. Blocks briefly for the current job to finish. */
void p2c_shutdown(void);

#ifdef __cplusplus
}
#endif
#endif /* PRINTERTOCUPS_H */
