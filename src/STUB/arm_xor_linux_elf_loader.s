.section .text
.global loader_entry_point

.macro save_regs
    push {r0, r1, r2, r3, r11, lr}
.endm

// Restore registers macro
.macro restore_regs
    pop {r0, r1, r2, r3, r11, lr}
.endm

loader_entry_point:
    //save flag
    mrs r8, cpsr
    //save registers
    save_regs

    // PIE offset calculation
    adr     r4, loader_entry_point
    adr     r5, info_offset
    ldr     r5, [r5]
    sub     r4,  r4, r5             // r4 = PIE offset

start_unpacking:
    adr     r0, info_addr
    ldr     r0, [r0]        // addr

    adr     r1, info_size
    ldr     r1, [r1]        // size

    adr     r2, info_key
    ldr     r2, [r2]        // key

    add     r0, r0, r4      // add PIE offset to addr
    add     r1, r1, r0      // end addr

loop:
    ldrb    r3, [r0]
    eor     r3, r3, r2
    strb    r3, [r0]
    ror     r2, r2, #4
    add     r0, r0, #1
    cmp     r0, r1
    bne    loop

    // Restore registers
    restore_regs
    // Restore flag
    msr cpsr, r8

    ldr     r9, info_entry
    mov     pc, r9
    nop

// random values here, to be patched
info_start:
info_entry:     .word 0xeeeeeeee
info_key:       .word 0xaaaaaaaa
info_addr:      .word 0xbbbbbbbb
info_size:      .word 0xcccccccc
info_offset:    .word 0xdddddddd

