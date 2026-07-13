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

/* --- printer capabilities, resolved from CUPS via IPP (cupsGetDestInfo + cupsFindDest*) ----------
 * This is what WP's own printer-capability model (the .prs-derived struct) gets populated from, so
 * WP's Page Setup / Print dialogs reflect the REAL queue instead of a frozen Type1-PostScript .prs.
 * Every list is best-effort: a count of 0 / empty string means CUPS did not report that attribute
 * for this queue (WP can then fall back to its defaults). PPDs are deprecated in current CUPS, so
 * this uses the IPP dest-info path exclusively. */
enum { P2C_MAX_MEDIA = 96, P2C_MAX_RES = 16, P2C_MAX_SOURCE = 24 };

typedef struct {
    int  ok;                              /* 1 = dest-info obtained; 0 = query failed (use WP defaults) */

    /* media / page sizes. `media[]` are PWG self-describing names ("iso_a4_210x297mm",
     * "na_letter_8.5x11in"); dimensions are in MICRONS (0 if CUPS gave a name but no size). */
    int  n_media;
    char media[P2C_MAX_MEDIA][64];
    int  media_w_um[P2C_MAX_MEDIA];
    int  media_h_um[P2C_MAX_MEDIA];
    char media_default[64];

    /* resolutions, in DPI (square; the x resolution if non-square). */
    int  n_res;
    int  res_dpi[P2C_MAX_RES];
    int  res_default_dpi;

    /* input sources / trays (IPP keywords: "main", "tray-1", "auto", "manual", ...). */
    int  n_source;
    char source[P2C_MAX_SOURCE][64];

    /* boolean capabilities. */
    int  color;                           /* 1 = a color print-color-mode is supported */
    int  duplex;                          /* 1 = two-sided ("sides") supported */
    int  duplex_default;                  /* 1 = the queue defaults to two-sided */
} P2CCaps;

/* Bring up libcups + the worker thread(s). Idempotent. Returns 0 on success, -1 if libcups is
 * unavailable (in which case p2c_submit/p2c_enum degrade to no-ops / 0). */
int  p2c_init(void);

/* Enumerate CUPS destinations into out[0..max-1]; returns the count written (>=0) or -1 on error.
 * Thread-safe. Returns the PREFETCHED cache when warm (instant, non-blocking) — see p2c_prefetch;
 * only the very first call before any prefetch does a live (blocking) cupsGetDests. */
int  p2c_enum(P2CPrinter *out, int max);

/* Warm the destination cache on a detached background thread so a later p2c_enum never blocks WP's
 * UI thread (the enumeration hook must return as fast as the old IPC did). Idempotent; safe to call
 * at library init. Returns 0 if the refresh was started (or already warm), -1 if libcups is absent. */
int  p2c_prefetch(void);

/* Resolve one queue's capabilities into *out (media/page-sizes, resolutions, sources, color,
 * duplex) via CUPS IPP. `dest` NULL/"" = the CUPS default destination. Returns 0 on success
 * (out->ok set), -1 if libcups/dest-info is unavailable (out zeroed, out->ok == 0). Thread-safe;
 * synchronous (a capability query, not a job) — cheap enough to call when a print dialog opens. */
int  p2c_caps(const char *dest, P2CCaps *out);

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
