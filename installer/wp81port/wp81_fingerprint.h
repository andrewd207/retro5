/* wp81_fingerprint.h -- WHITELIST of xwp builds retroXt81's hardcoded detour/shim
 * addresses are valid for.  These are POST-PATCH md5s: the value of the fully
 * INSTALLED binary (after the installer's libc.so.5->retro5.so retarget + any morph
 * patches), i.e. what actually runs.  If the loaded binary's MD5 isn't in this list,
 * the addresses are meaningless and patching would corrupt a DIFFERENT binary, so the
 * reskin refuses (WP runs 100% stock).
 *
 * Only add BRIDGED (libc6 / retro5.so) builds -- a stock libc5 xwp can't load this
 * libc6 .so at all, so it never belongs here.
 *
 * Add a build:  md5sum <installed xwp>  -> append a 16-byte row to WP81_XWP_MD5S.
 * The installer (Engine.reskin) checks the same list post-patch before enabling. */
#ifndef WP81_FINGERPRINT_H
#define WP81_FINGERPRINT_H

/* WP81_XWP_MD5S(M): X-macro, one M(...) per whitelisted post-patch build.
 * Row = 16 md5 bytes + a human tag. */
#define WP81_XWP_MD5S(M) \
    M(0x04,0x7a,0x89,0x96,0xbe,0xf8,0x47,0x04,0xea,0x5b,0x11,0x1a,0xc9,0xb3,0xef,0x55, \
      "WP 8.1 Linux (Corel), retro5-bridged  047a8996bef84704ea5b111ac9b3ef55")

#endif /* WP81_FINGERPRINT_H */
