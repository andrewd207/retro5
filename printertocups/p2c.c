/* p2c.c — printer-to-CUPS backend. See p2c.h.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * Design:
 *  - libcups is dlopen'd RTLD_DEEPBIND so its glibc/gnutls deps stay isolated from WP's libc5 shim
 *    (the same hazard cairo/librsvg have in retro5). We call it only through dlsym'd pointers, so we
 *    never link it and need no dev symlink.
 *  - A single worker thread drains a mutex+condvar job queue. p2c_submit() copies the body + options
 *    and returns immediately; the worker does cupsCreateJob/StartDocument/WriteRequestData/
 *    FinishDocument off the caller's thread. One worker => submissions are serialized, which keeps
 *    the libcups per-thread HTTP state trivially safe; the queue itself is the only shared state and
 *    is fully mutex-guarded.
 */
#include "p2c.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>

#ifndef RTLD_DEEPBIND
#define RTLD_DEEPBIND 0x00008
#endif

/* Minimal CUPS types (we dlopen libcups, so we don't include cups.h / link -lcups). */
typedef struct { char *name, *value; } cups_option_t;
typedef struct { char *name, *instance; int is_default; int num_options; cups_option_t *options; } cups_dest_t;

/* dlsym'd libcups entry points (http_t* is passed as NULL = CUPS_HTTP_DEFAULT). */
static struct {
    int   ready;
    void *h;
    int         (*GetDests)(cups_dest_t **);
    void        (*FreeDests)(int, cups_dest_t *);
    const char *(*GetOption)(const char *, int, cups_option_t *);
    int         (*AddOption)(const char *, const char *, int, cups_option_t **);
    void        (*FreeOptions)(int, cups_option_t *);
    int         (*CreateJob)(void *, const char *, const char *, int, cups_option_t *);
    int         (*StartDocument)(void *, const char *, int, const char *, const char *, int);
    int         (*WriteRequestData)(void *, const char *, size_t);
    int         (*FinishDocument)(void *, const char *);
} cu;

/* ---- job queue ---- */
typedef struct p2c_job {
    struct p2c_job *next;
    char   dest[128], title[128], format[64];
    char  *data; size_t len;
    char **onames, **ovals; int nopt;
    long   handle;
} p2c_job;

static pthread_mutex_t q_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  q_cv  = PTHREAD_COND_INITIALIZER;   /* worker wakes on new job or stop */
static pthread_cond_t  q_idle = PTHREAD_COND_INITIALIZER;  /* signalled when queue fully drained */
static p2c_job *q_head, *q_tail;
static int      q_pending;                                 /* queued + in-flight */
static int      q_stop;
static long     q_next_handle = 1;
static pthread_t q_worker;
static int      q_started;

static int p2c_load_cups(void) {
    if (cu.ready) return 1;
    cu.h = dlopen("libcups.so.2", RTLD_NOW | RTLD_GLOBAL | RTLD_DEEPBIND);
    if (!cu.h) cu.h = dlopen("libcups.so.2", RTLD_NOW | RTLD_DEEPBIND);
    if (!cu.h) return 0;
    cu.GetDests         = (int  (*)(cups_dest_t **))                          dlsym(cu.h, "cupsGetDests");
    cu.FreeDests        = (void (*)(int, cups_dest_t *))                      dlsym(cu.h, "cupsFreeDests");
    cu.GetOption        = (const char *(*)(const char *, int, cups_option_t *)) dlsym(cu.h, "cupsGetOption");
    cu.AddOption        = (int  (*)(const char *, const char *, int, cups_option_t **)) dlsym(cu.h, "cupsAddOption");
    cu.FreeOptions      = (void (*)(int, cups_option_t *))                    dlsym(cu.h, "cupsFreeOptions");
    cu.CreateJob        = (int  (*)(void *, const char *, const char *, int, cups_option_t *)) dlsym(cu.h, "cupsCreateJob");
    cu.StartDocument    = (int  (*)(void *, const char *, int, const char *, const char *, int)) dlsym(cu.h, "cupsStartDocument");
    cu.WriteRequestData = (int  (*)(void *, const char *, size_t))            dlsym(cu.h, "cupsWriteRequestData");
    cu.FinishDocument   = (int  (*)(void *, const char *))                    dlsym(cu.h, "cupsFinishDocument");
    if (!cu.GetDests || !cu.CreateJob || !cu.StartDocument || !cu.WriteRequestData || !cu.FinishDocument)
        return 0;
    cu.ready = 1;
    return 1;
}

/* Hand one job to CUPS. Runs on the worker thread; http_t* = NULL = the thread's default connection. */
static void p2c_spool(p2c_job *j) {
    cups_option_t *opts = 0; int nopt = 0, i, jobid;
    const char *dest = j->dest[0] ? j->dest : 0;           /* NULL -> CUPS default destination */
    if (cu.AddOption)
        for (i = 0; i < j->nopt; i++)
            nopt = cu.AddOption(j->onames[i], j->ovals[i], nopt, &opts);
    jobid = cu.CreateJob((void *)0, dest, j->title[0] ? j->title : "WordPerfect", nopt, opts);
    if (jobid > 0) {
        cu.StartDocument((void *)0, dest, jobid, "document", j->format, 1 /*last*/);
        if (j->data && j->len) cu.WriteRequestData((void *)0, (const char *)j->data, j->len);
        cu.FinishDocument((void *)0, dest);
    }
    if (opts && cu.FreeOptions) cu.FreeOptions(nopt, opts);
}

static void p2c_job_free(p2c_job *j) {
    int i;
    if (!j) return;
    free(j->data);
    for (i = 0; i < j->nopt; i++) { free(j->onames[i]); free(j->ovals[i]); }
    free(j->onames); free(j->ovals);
    free(j);
}

static void *p2c_worker(void *arg) {
    (void)arg;
    for (;;) {
        p2c_job *j;
        pthread_mutex_lock(&q_mtx);
        while (!q_head && !q_stop) pthread_cond_wait(&q_cv, &q_mtx);
        if (q_stop && !q_head) { pthread_mutex_unlock(&q_mtx); break; }
        j = q_head; q_head = j->next; if (!q_head) q_tail = 0;
        pthread_mutex_unlock(&q_mtx);

        p2c_spool(j);                                      /* the slow part — off the caller's thread */
        p2c_job_free(j);

        pthread_mutex_lock(&q_mtx);
        if (--q_pending == 0) pthread_cond_broadcast(&q_idle);
        pthread_mutex_unlock(&q_mtx);
    }
    return 0;
}

int p2c_init(void) {
    int rc = 0;
    pthread_mutex_lock(&q_mtx);
    if (!p2c_load_cups()) { pthread_mutex_unlock(&q_mtx); return -1; }
    if (!q_started) {
        q_stop = 0;
        if (pthread_create(&q_worker, 0, p2c_worker, 0) == 0) q_started = 1;
        else rc = -1;
    }
    pthread_mutex_unlock(&q_mtx);
    return rc;
}

int p2c_enum(P2CPrinter *out, int max) {
    cups_dest_t *dests = 0; int n, i, got = 0;
    if (!p2c_load_cups() || !out || max <= 0) return -1;
    n = cu.GetDests(&dests);
    for (i = 0; i < n && got < max; i++) {
        const char *info = cu.GetOption ? cu.GetOption("printer-info", dests[i].num_options, dests[i].options) : 0;
        strncpy(out[got].name, dests[i].name ? dests[i].name : "", sizeof out[got].name - 1);
        out[got].name[sizeof out[got].name - 1] = 0;
        strncpy(out[got].info, info ? info : "", sizeof out[got].info - 1);
        out[got].info[sizeof out[got].info - 1] = 0;
        out[got].is_default = dests[i].is_default ? 1 : 0;
        got++;
    }
    if (dests && cu.FreeDests) cu.FreeDests(n, dests);
    return got;
}

long p2c_submit(const char *dest, const char *title, const char *format,
                const void *data, size_t len, const P2COpt *opts, int nopt) {
    p2c_job *j; int i; long handle;
    if (p2c_init() != 0) return -1;                        /* ensure cups + worker up */
    j = (p2c_job *)calloc(1, sizeof *j);
    if (!j) return -1;
    if (dest)   { strncpy(j->dest,  dest,   sizeof j->dest  - 1); }
    if (title)  { strncpy(j->title, title,  sizeof j->title - 1); }
    strncpy(j->format, (format && *format) ? format : P2C_POSTSCRIPT, sizeof j->format - 1);
    if (data && len) { j->data = malloc(len); if (!j->data) { free(j); return -1; }
                       memcpy(j->data, data, len); j->len = len; }
    if (nopt > 0 && opts) {
        j->onames = (char **)calloc(nopt, sizeof(char *));
        j->ovals  = (char **)calloc(nopt, sizeof(char *));
        if (!j->onames || !j->ovals) { p2c_job_free(j); return -1; }
        for (i = 0; i < nopt; i++) {
            j->onames[i] = strdup(opts[i].name  ? opts[i].name  : "");
            j->ovals[i]  = strdup(opts[i].value ? opts[i].value : "");
            j->nopt = i + 1;
        }
    }
    pthread_mutex_lock(&q_mtx);
    handle = j->handle = q_next_handle++;
    j->next = 0;
    if (q_tail) q_tail->next = j; else q_head = j;
    q_tail = j;
    q_pending++;
    pthread_cond_signal(&q_cv);
    pthread_mutex_unlock(&q_mtx);
    return handle;
}

int p2c_wait_idle(int timeout_ms) {
    int rc = 0;
    pthread_mutex_lock(&q_mtx);
    if (timeout_ms < 0) {
        while (q_pending > 0) pthread_cond_wait(&q_idle, &q_mtx);
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec  += timeout_ms / 1000;
        ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
        while (q_pending > 0)
            if (pthread_cond_timedwait(&q_idle, &q_mtx, &ts) != 0) { rc = q_pending ? -1 : 0; break; }
    }
    pthread_mutex_unlock(&q_mtx);
    return rc;
}

void p2c_shutdown(void) {
    pthread_mutex_lock(&q_mtx);
    if (!q_started) { pthread_mutex_unlock(&q_mtx); return; }
    q_stop = 1;
    pthread_cond_broadcast(&q_cv);
    pthread_mutex_unlock(&q_mtx);
    pthread_join(q_worker, 0);
    q_started = 0;
}
