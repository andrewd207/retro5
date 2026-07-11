/* wp81_fpguard.c -- fail-safe build-identity guard for the 8.1 detour port.
 *
 * retroXt81 patches ~30 HARDCODED absolute addresses in xwp and tail-jumps to ~29
 * more (rx81_shim).  Those addresses are valid ONLY for the exact build they were
 * mapped from.  Before touching anything, wp81_fingerprint_ok() MD5s the running
 * executable (/proc/self/exe) and compares it to the expected hash; on any mismatch
 * the caller must install NOTHING, so a different/updated xwp runs unmodified.
 *
 * Self-contained: raw i386 syscalls only (no libc/retro5 symbol-collision risk, same
 * rationale as detour81.c), and a compact RFC-1321 MD5.  Output matches `md5sum`.
 */
#include <stdint.h>
#include <string.h>
#include "wp81_fingerprint.h"

/* --- raw i386 syscalls (ebx is the PIC GOT base; save/restore around int 0x80) --- */
static inline long sys3(long nr, long a, long b, long c) {
    long r;
    __asm__ volatile("xchg %%ebx,%1\n\tint $0x80\n\txchg %%ebx,%1"
                     : "=a"(r), "+r"(a) : "0"(nr), "c"(b), "d"(c) : "memory");
    return r;
}
#define SYS_open 5
#define SYS_read 3
#define SYS_close 6

/* --------------------------------- MD5 (RFC 1321) --------------------------------- */
typedef struct { uint32_t a,b,c,d; uint64_t len; unsigned char buf[64]; unsigned n; } md5_t;
static uint32_t rol(uint32_t x,int c){ return (x<<c)|(x>>(32-c)); }
static void md5_block(md5_t *m, const unsigned char *p) {
    static const uint32_t K[64]={
      0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
      0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
      0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
      0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
      0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
      0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
      0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
      0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
    static const int S[64]={7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
      5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
      4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
      6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
    uint32_t M[16];
    for (int i=0;i<16;i++)
        M[i]=(uint32_t)p[i*4]|((uint32_t)p[i*4+1]<<8)|((uint32_t)p[i*4+2]<<16)|((uint32_t)p[i*4+3]<<24);
    uint32_t A=m->a,B=m->b,C=m->c,D=m->d;
    for (int i=0;i<64;i++){
        uint32_t F; int g;
        if (i<16){ F=(B&C)|(~B&D); g=i; }
        else if (i<32){ F=(D&B)|(~D&C); g=(5*i+1)&15; }
        else if (i<48){ F=B^C^D; g=(3*i+5)&15; }
        else { F=C^(B|~D); g=(7*i)&15; }
        F=F+A+K[i]+M[g];
        A=D; D=C; C=B; B=B+rol(F,S[i]);
    }
    m->a+=A; m->b+=B; m->c+=C; m->d+=D;
}
static void md5_init(md5_t *m){ m->a=0x67452301;m->b=0xefcdab89;m->c=0x98badcfe;m->d=0x10325476;m->len=0;m->n=0; }
static void md5_update(md5_t *m, const unsigned char *p, unsigned len){
    m->len+=len;
    while (len){
        unsigned k=64-m->n; if (k>len) k=len;
        memcpy(m->buf+m->n,p,k); m->n+=k; p+=k; len-=k;
        if (m->n==64){ md5_block(m,m->buf); m->n=0; }
    }
}
static void md5_final(md5_t *m, unsigned char out[16]){
    uint64_t bits=m->len*8;
    unsigned char pad=0x80; md5_update(m,&pad,1);
    unsigned char z=0; while (m->n!=56) md5_update(m,&z,1);
    unsigned char lb[8]; for (int i=0;i<8;i++) lb[i]=(unsigned char)(bits>>(8*i));
    md5_update(m,lb,8);
    uint32_t v[4]={m->a,m->b,m->c,m->d};
    for (int i=0;i<4;i++){ out[i*4]=v[i]; out[i*4+1]=v[i]>>8; out[i*4+2]=v[i]>>16; out[i*4+3]=v[i]>>24; }
}

/* Stream /proc/self/exe through MD5.  Returns file size, or -1 on error. */
static long exe_md5(unsigned char out[16]) {
    int fd = (int)sys3(SYS_open, (long)"/proc/self/exe", 0 /*O_RDONLY*/, 0);
    if (fd < 0) return -1;
    md5_t m; md5_init(&m);
    static unsigned char buf[65536];
    long total = 0, r;
    while ((r = sys3(SYS_read, fd, (long)buf, sizeof buf)) > 0) {
        md5_update(&m, buf, (unsigned)r);
        total += r;
    }
    sys3(SYS_close, fd, 0, 0);
    if (r < 0) return -1;
    md5_final(&m, out);
    return total;
}

/* 1 = the running exe is a whitelisted (post-patch) build, safe to patch; 0 = do NOT.
 * If got16 != NULL, the computed hash is written there (for logging on mismatch). */
int wp81_fingerprint_ok(unsigned char got16[16]) {
    unsigned char got[16];
    long sz = exe_md5(got);
    if (got16) memcpy(got16, got, 16);
    if (sz < 0) return 0;
#define M(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15,tag) do { \
        static const unsigned char want[16] = {b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15}; \
        if (memcmp(got, want, 16) == 0) return 1; \
    } while (0);
    WP81_XWP_MD5S(M)
#undef M
    return 0;
}
