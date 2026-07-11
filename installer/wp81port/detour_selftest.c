/* Proves the detour81 engine end-to-end on a native i386 function:
 *  - target real_add(a,b) = a+b   (known prologue: push ebp;mov esp,ebp;mov 8(ebp),eax = 6 bytes)
 *  - hook   my_add(a,b)   = orig_add(a,b) * 10
 * Expect: after install, real_add(3,4) -> 70 (hook ran), orig_add(3,4) -> 7 (trampoline preserves original).
 */
#include <stdio.h>
#include "detour81.h"

/* real_add with an explicit, position-independent prologue so its steal is known (6). */
__asm__(".text\n"
        ".globl real_add\n"
        "real_add:\n"
        "  push %ebp\n"            /* 55            */
        "  mov  %esp, %ebp\n"      /* 89 e5         */
        "  mov  8(%ebp), %eax\n"   /* 8b 45 08      -> 6 bytes >= 5 */
        "  add  12(%ebp), %eax\n"
        "  pop  %ebp\n"
        "  ret\n");
extern int real_add(int, int);

static int (*orig_add)(int, int);
static int my_add(int a, int b) { return orig_add(a, b) * 10; }

#include <stdarg.h>
static void logf_(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); }

int main(void) {
    detour_log = logf_;
    printf("before: real_add(3,4) = %d\n", real_add(3, 4));

    detour_t d[1] = {{ "real_add", (void *)real_add, (void *)my_add, (void **)&orig_add, 6 }};
    int ok = detour_install(d, 1);

    int hooked = real_add(3, 4);   /* should route through my_add -> 70 */
    int orig   = orig_add(3, 4);   /* trampoline -> original -> 7        */
    printf("installed=%d\nafter:  real_add(3,4) = %d (expect 70)\n        orig_add(3,4) = %d (expect 7)\n",
           ok, hooked, orig);

    int pass = (ok == 1 && hooked == 70 && orig == 7);
    printf("%s\n", pass ? "SELFTEST PASS" : "SELFTEST FAIL");
    return !pass;
}
