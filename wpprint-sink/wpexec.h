/* wpexec.h — run a command the way wpexc does (fork/pipe/exec + wait).
 * SPDX-License-Identifier: MIT
 *
 * Faithful to wpexc's exec primitive (FUN_ @ ~0x0805a0f0 in the 8.0 build):
 * pipe(); fork(); child dup2()s stdout onto the pipe and stderr onto /dev/null,
 * then execvp(file, argv); parent closes the write end, waits (EINTR/SIGCLD
 * aware), and returns a status. Optionally captures the child's stdout.
 */
#ifndef WPEXEC_H
#define WPEXEC_H
#include <stddef.h>

/* Run argv[0]=file with argv. If out!=NULL, capture up to *outcap bytes of the
 * child's stdout into out and set *outcap to the amount read. Returns:
 *   >=0  the child's exit status (WEXITSTATUS), or
 *   WP_ST_PIPE / WP_ST_FORK on setup failure (see wpproto.h).
 * feed/feedlen, if non-NULL, is written to the child's stdin first.
 */
int wp_run(const char *file, char *const argv[],
           const char *feed, size_t feedlen,
           char *out, size_t *outcap);

#endif /* WPEXEC_H */
