/* AAPCS64 scalar call bridge.
 *
 * void ios_native_call_aapcs64(
 *     void *target, const uint64_t gpr[8],
 *     const uint64_t fpr[8], const uint8_t *stack,
 *     size_t stack_size, struct native_call_result *result);
 *
 * result receives x0 followed by the low 64 bits of v0.
 */

.text
.p2align 2

#if defined(__APPLE__)
.globl _ios_native_call_aapcs64
_ios_native_call_aapcs64:
#else
.global ios_native_call_aapcs64
.type ios_native_call_aapcs64, %function
ios_native_call_aapcs64:
#endif
    .cfi_startproc
    stp     x29, x30, [sp, #-32]!
    str     x19, [sp, #16]
    .cfi_def_cfa_offset 32
    .cfi_offset w29, -32
    .cfi_offset w30, -24
    .cfi_offset w19, -16
    mov     x29, sp
    .cfi_def_cfa w29, 32

    mov     x16, x0
    mov     x9, x1
    mov     x10, x2
    mov     x11, x3
    mov     x12, x4
    mov     x19, x5

    cbz     x12, 2f
    add     x13, x12, #15
    and     x13, x13, #~15
    sub     sp, sp, x13

    mov     x14, #0
1:
    ldrb    w15, [x11, x14]
    strb    w15, [sp, x14]
    add     x14, x14, #1
    cmp     x14, x12
    b.lo    1b

2:
    ldp     d6, d7, [x10, #48]
    ldp     d4, d5, [x10, #32]
    ldp     d2, d3, [x10, #16]
    ldp     d0, d1, [x10]

    ldp     x6, x7, [x9, #48]
    ldp     x4, x5, [x9, #32]
    ldp     x2, x3, [x9, #16]
    ldp     x0, x1, [x9]

    blr     x16

    str     x0, [x19]
    str     d0, [x19, #8]
    mov     sp, x29
    ldr     x19, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret
    .cfi_endproc

#if !defined(__APPLE__)
.size ios_native_call_aapcs64, .-ios_native_call_aapcs64
#endif

#if defined(__linux__) || defined(__ANDROID__)
.section .note.GNU-stack,"",%progbits
#endif
