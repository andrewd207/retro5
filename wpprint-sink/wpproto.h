/* wpproto.h — WordPerfect 8 (Linux) print IPC protocol constants.
 * SPDX-License-Identifier: MIT
 *
 * Clean-room, reverse-engineered from the 8.0.0076 build (wpexc_decompiled.c +
 * ELF string extraction). See docs/print-ipc-protocol.md. The wire format is a
 * newline-terminated TEXT protocol; the handshake line is "e_wpexc1".
 *
 * The message vocabulary is wpexc's token table (@0x0806af90). Tokens are ASCII;
 * a message is <token> optionally followed by payload field(s), then '\n'.
 */
#ifndef WPPROTO_H
#define WPPROTO_H

#define WP_MSG_TERM        '\n'          /* line terminator (DAT_0806aee8)      */
#define WP_HANDSHAKE       "e_wpexc1"    /* protocol v1 handshake, sent first    */

/* --- job lifecycle / control (editor -> queue) --- */
#define WP_JOB             "e_job"       /* begin a job (+ job data)             */
#define WP_FORM            "e_form"      /* select form / paper                  */
#define WP_DEVICE          "e_device"    /* select printer device               */
#define WP_GO              "e_go"        /* start printing                       */
#define WP_PRINT           "e_print"     /* print (job active)                   */
#define WP_STOP            "e_stop"      /* stop                                 */

/* --- status (queue -> editor) --- */
#define WP_SERVEST         "e_servest"   /* server established                   */
#define WP_STARTED         "e_started"   /* job started                          */
#define WP_QUEUED          "e_queued"    /* job queued                           */
#define WP_PROC            "e_proc"      /* processing                           */
#define WP_PROCSPL         "e_procspl"   /* processing spool                     */
#define WP_DONE            "e_done"      /* job finished                         */
#define WP_HELD            "e_held"
#define WP_AHELD           "e_aheld"
#define WP_KILLED          "e_killed"
#define WP_REMOVED         "e_removed"
#define WP_DOWN            "e_down"
#define WP_STARTED_U       "e_ustart"
#define WP_UEXITING        "e_uexiting"
#define WP_NOTAVL          "e_notavl"
#define WP_UNKNOWN         "e_unknown"
#define WP_CLOSED          "e_closed"

/* --- session control --- */
#define WP_RSTOK           "e_rstok"     /* reset ok                             */
#define WP_NEXCMSG         "e_nexcmsg"   /* next exec message                    */
#define WP_MQDNE           "e_mqdne"     /* message-queue done                   */
#define WP_VERBON          "e_verbon"
#define WP_VERBOFF         "e_verboff"
#define WP_NOVERB          "e_noverb"
#define WP_USAGE           "e_usage"
#define WP_NOTSU           "e_notsu"     /* not supported                        */
#define WP_NOTSTART        "e_notstart"

/* --- errors --- */
#define WP_ERROR           "e_error"
#define WP_ERROR1          "e_error1"
#define WP_EFIFO           "e_fifo"
#define WP_ER_SPOOL        "er_spool"
#define WP_ER_BADPORT      "er_badport"
#define WP_ER_BADFORK      "er_badfork"

/* --- rendezvous (docs/print-ipc-protocol.md: $WPCOM, default /tmp) --- */
#define WP_RENDEZVOUS_ENV  "WPCOM"       /* dir; fallback $SHTMP, then /tmp       */
#define WP_RENDEZVOUS_DIR  "/tmp"
#define WP_SOCK_PREFIX     "wpc-"        /* socket/fifo name prefix (DAT_08068adf)*/
#define WP_FIFO_MAILBOX    ".wpexc8.man" /* FIFO mailbox name                     */
#define WP_LOCK            ".wpexc8.LCK"

/* --- status codes seen in wpexc (map to the er_* tokens) ------------------- */
#define WP_ST_OK           0
#define WP_ST_PIPE         0x800016      /* pipe() failed                        */
#define WP_ST_FORK         0x800024      /* fork()/exec failed  -> er_badfork    */
#define WP_ST_SPOOL        0x800207      /* spool/fifo error    -> er_spool      */

/* ======================================================================== */
/* Shared protocol I/O (wpproto.c) — used by wpsink, wpexecd, ...            */
/* ======================================================================== */
#include <stddef.h>
#include <sys/types.h>

/* Resolve the rendezvous dir: $WPCOM -> $SHTMP -> /tmp. */
void   wp_rendezvous_dir(char *out, size_t n);

/* Read one '\n'-terminated line (newline stripped). >0 len, 0 EOF, -1 error. */
ssize_t wp_read_line(int fd, char *buf, size_t cap);

/* Write "<token>\n". 0 ok, -1 error. */
int    wp_write_msg(int fd, const char *token);

/* Stream nbytes of body into a spool command (stdin). Returns its exit status,
 * or -1 on spawn failure. */
int    wp_spool(const char *cmd, const char *body, size_t nbytes);

#endif /* WPPROTO_H */
