/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Andrew Haines
 */

/* setjmp5.S - libc5 i386 __setjmp/longjmp.
 * libc5 jmp_buf is 6 words: {ebx, esi, edi, ebp, esp, eip}.
 * We implement these ourselves so the buffer layout matches WP's exactly
 * (glibc's jmp_buf has extra sigmask fields we must not depend on).
 */
    .text

    .globl __setjmp
    .type  __setjmp,@function
__setjmp:
    movl    4(%esp), %eax      /* jmp_buf */
    movl    %ebx,  0(%eax)
    movl    %esi,  4(%eax)
    movl    %edi,  8(%eax)
    movl    %ebp, 12(%eax)
    leal    4(%esp), %ecx      /* caller's esp (past return addr) */
    movl    %ecx, 16(%eax)
    movl    0(%esp), %ecx      /* return address */
    movl    %ecx, 20(%eax)
    xorl    %eax, %eax
    ret
    .size __setjmp,.-__setjmp

/* provide _setjmp/setjmp as aliases (register-only save) in case WP uses them */
    .globl _setjmp
    .set   _setjmp, __setjmp
    .globl setjmp
    .set   setjmp, __setjmp

    .globl longjmp
    .type  longjmp,@function
longjmp:
    movl    4(%esp), %edx      /* jmp_buf */
    movl    8(%esp), %eax      /* return value */
    testl   %eax, %eax
    jnz     1f
    incl    %eax               /* longjmp(env,0) must return 1 */
1:
    movl     0(%edx), %ebx
    movl     4(%edx), %esi
    movl     8(%edx), %edi
    movl    12(%edx), %ebp
    movl    16(%edx), %esp
    movl    20(%edx), %ecx
    jmp     *%ecx
    .size longjmp,.-longjmp

    .globl _longjmp
    .set   _longjmp, longjmp

    .section .note.GNU-stack,"",@progbits
