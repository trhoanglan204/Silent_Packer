.section .text
.global loader_entry_point

// Save registers macro
// rax ~ x8
// rdi ~ x0
// rsi ~ x1
// rdx ~ x2
// rcx ~ x3
// rsp ~ x29
// lr ~ x30
.macro save_regs
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x29, x30, [sp, #-16]!
.endm

// Restore registers macro
.macro restore_regs
    ldp x29, x30, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
.endm

loader_entry_point:
    // save flag
    mrs x15, NZCV
    // Save registers
    save_regs

    // PIE offset calculation
    adr     x12, loader_entry_point
    adr     x13, info_offset
    ldr     x13, [x13]
    sub     x12, x12, x13           // x12 = PIE offset

start_unpacking:
    adr     x0, info_addr
    ldr     x0, [x0]        // addr

    adr     x1, info_size
    ldr     x1, [x1]        // size

    adr     x2, info_key
    ldr     x2, [x2]        // key

    add     x0, x0, x12     // add PIE offset to addr
    add     x1, x1, x0      // end addr

loop:
    ldrb    w3, [x0]
    eor     w3, w3, w2
    strb    w3, [x0]
    ror     x2, x2, #8
    add     x0, x0, #1
    cmp     x0, x1
    b.ne    loop

    // Restore registers
    restore_regs
    // Restore flag
    msr NZCV, x15

    ldr     x30, info_entry
    br      x30
    nop

// random values here, to be patched
info_start:
info_entry:     .quad 0xeeeeeeeeeeeeeeee
info_key:       .quad 0xaaaaaaaaaaaaaaaa
info_addr:      .quad 0xbbbbbbbbbbbbbbbb
info_size:      .quad 0xcccccccccccccccc
info_offset:    .quad 0xdddddddddddddddd

