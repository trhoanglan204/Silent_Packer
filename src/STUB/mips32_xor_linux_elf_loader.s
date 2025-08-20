.section .text
.global loader_entry_point

# Register notes:
# $a0 ~ edi
# $a1 ~ esi
# $a2 ~ edx
# $a3 ~ ecx
# $v0 ~ eax
# $sp ~ esp
# $ra - return address

loader_entry_point:
    addiu   $sp, $sp, -16
    sw      $a0, 0($sp)
    sw      $a1, 4($sp)
    sw      $a2, 8($sp)
    sw      $a3, 12($sp)
    sw      $ra, 16($sp)

    bal here

here:
    # PIE offset calculation
    addiu   $s0, $ra, loader_entry_point - here
    addiu   $s1, $ra, info_offset - here
    lw      $s1, 0($s1)
    subu    $s0, $s0, $s1       # s0 = PIE offset
    nop

    addiu   $s2, $ra, start_unpacking - here
    jr      $s2
    nop

start_unpacking:
    addiu   $s4, $ra, info_entry - here

    addiu   $s2, $ra, info_addr - here
    lw      $a0, 0($s2)

    addiu   $s2, $ra, info_size - here
    lw      $a3, 0($s2)

    addiu   $s2, $ra, info_key - here
    lw      $a2, 0($s2)

    addu    $a0, $a0, $t0
    addu    $a3, $a3, $a0

loop:
    lbu     $s1, 0($a0)
    xor     $s1, $s1, $a2
    sb      $s1, 0($a0)

    # Manual rotate right 32-bit (4-bits)
    sll     $s2, $a2, 28
    srl     $a2, $a2, 4
    or      $a2, $a2, $s2

    addiu   $a0, $a0, 1

    subu    $s3, $a3, $a0
    sltu    $s3, $zero, $s3
    bnez    $s3, loop
    nop

    lw      $a0, 0($sp)
    lw      $a1, 4($sp)
    lw      $a2, 8($sp)
    lw      $a3, 12($sp)
    lw      $ra, 16($sp)
    addiu   $sp, $sp, 16

    lw      $t9, 0($s4)
    jr      $t9
    nop

# random values here, to be patched
info_start:
info_entry:     .word 0xeeeeeeee
info_key:       .word 0xaaaaaaaa
info_addr:      .word 0xbbbbbbbb
info_size:      .word 0xcccccccc
info_offset:    .word 0xdddddddd

