/* detour81.c -- x86-32 inline-detour engine.  See detour81.h.
 *
 * Mechanics per target:
 *   trampoline = [ relocated `steal` prologue bytes ][ E9 jmp -> target+steal ]
 *   target[0..4]        = E9 jmp -> hook              (5-byte rel32 jump)
 *   target[5..steal-1]  = 90 (nop padding, tidy disasm)
 *
 * The stolen prologue bytes are copied verbatim; patch81.py has already PROVEN
 * (with capstone) that for every WP 8.1 target the stolen region contains no
 * relative branch and is not the destination of any internal jump, so a byte
 * copy is position-independent and safe.
 *
 * Memory ops go through raw int-0x80 syscalls, NOT the libc wrappers: under
 * LD_PRELOAD the process also carries retro5's libc5 exports in a flat symbol
 * namespace, and binding to a libc5 mmap/mprotect (different ABI: old mmap took
 * a struct; libc5 mmap != glibc mmap2) would corrupt the call.  syscall numbers
 * are the stable kernel i386 ABI.
 */
#include "detour81.h"
#include <stdint.h>
#include <string.h>

/* --- raw i386 syscalls (avoid libc/retro5 symbol collisions) --------------- */
static inline long sys3(long nr, long a, long b, long c) {
    /* ebx is the PIC GOT base; save/restore it around the syscall. */
    long r;
    __asm__ volatile("xchg %%ebx, %1\n\t"
                     "int $0x80\n\t"
                     "xchg %%ebx, %1"
                     : "=a"(r), "+r"(a)
                     : "0"(nr), "c"(b), "d"(c)
                     : "memory");
    return r;
}
#define SYS_mprotect 125
#define PROT_R  0x1
#define PROT_W  0x2
#define PROT_X  0x4
#define PAGE 4096UL

static int xmprotect(void *addr, unsigned long len, int prot) {
    return (int)sys3(SYS_mprotect, (long)addr, (long)len, prot);
}

/* --- executable trampoline arena --------------------------------------------
 * A static buffer (in the .so's writable data) mprotect()ed to RWX on first use.
 * Avoids the fiddly 6-arg mmap2 (ebp/ebx under PIC) entirely. 64 KiB holds far
 * more than the ~30 * (steal+5) bytes we need. */
static unsigned char g_arena[0x10000] __attribute__((aligned(4096)));
static unsigned long  g_used;
static int            g_arena_exec;
static void *arena_alloc(unsigned n) {
    if (!g_arena_exec) {
        if (xmprotect(g_arena, sizeof g_arena, PROT_R | PROT_W | PROT_X) != 0)
            return 0;
        g_arena_exec = 1;
    }
    n = (n + 15u) & ~15u;                       /* 16-byte align each tramp */
    if (g_used + n > sizeof g_arena) return 0;
    void *p = g_arena + g_used;
    g_used += n;
    return p;
}

void (*detour_log)(const char *fmt, ...) = 0;
#define LOG(...) do { if (detour_log) detour_log(__VA_ARGS__); } while (0)

static int install_one(detour_t *d) {
    unsigned char *t = (unsigned char *)d->target;
    if (d->steal < 5) { LOG("detour %s: steal<5\n", d->name); return 0; }

    /* 1. trampoline: relocated prologue + jmp back to target+steal */
    unsigned char *tr = arena_alloc(d->steal + 5);
    if (!tr) { LOG("detour %s: no arena\n", d->name); return 0; }
    memcpy(tr, t, d->steal);
    tr[d->steal] = 0xE9;
    *(int32_t *)(tr + d->steal + 1) =
        (int32_t)((t + d->steal) - (tr + d->steal + 5));
    if (d->orig) *d->orig = tr;

    /* 2. patch target -> jmp hook (make code page writable across the span) */
    unsigned long pg   = (unsigned long)t & ~(PAGE - 1);
    unsigned long span = ((unsigned long)t + d->steal) - pg;
    span = (span + PAGE - 1) & ~(PAGE - 1);
    if (xmprotect((void *)pg, span, PROT_R | PROT_W | PROT_X) != 0) {
        LOG("detour %s: mprotect(rwx) failed\n", d->name);
        return 0;
    }
    t[0] = 0xE9;
    *(int32_t *)(t + 1) = (int32_t)((unsigned char *)d->hook - (t + 5));
    for (unsigned i = 5; i < d->steal; i++) t[i] = 0x90;
    xmprotect((void *)pg, span, PROT_R | PROT_X);   /* restore RX */

    LOG("detour %-26s @0x%08lx -> hook 0x%08lx  (steal %u, tramp 0x%08lx)\n",
        d->name, (unsigned long)t, (unsigned long)d->hook, d->steal,
        (unsigned long)tr);
    return 1;
}

int detour_install(detour_t *tab, int n) {
    int ok = 0;
    for (int i = 0; i < n; i++) ok += install_one(&tab[i]);
    LOG("detour_install: %d/%d installed\n", ok, n);
    return ok;
}
