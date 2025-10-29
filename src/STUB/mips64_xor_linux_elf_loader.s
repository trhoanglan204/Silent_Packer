.section .text
.global loader_entry_point

# Register notes:
# $a0 ~ rdi
# $a1 ~ rsi
# $a2 ~ rdx
# $a3 ~ rcx
# $v0 ~ rax
# $sp ~ rsp
# $ra - return address

loader_entry_point:
    daddiu  $sp, $sp, -32
    sd      $a0, 0($sp)
    sd      $a1, 8($sp)
    sd      $a2, 16($sp)
    sd      $a3, 24($sp)
    sd      $ra, 32($sp)

    bal here                        # branch-and-link: $ra = current PC + 8

here:
    # PIE offset calculation
    daddiu  $s0, $ra, loader_entry_point - here
    daddiu  $s1, $ra, info_offset - here
    ld      $s1, 0($s1)
    dsubu   $s0, $s0, $s1           # s0 = PIE offset
    nop

    daddiu  $s2, $ra, start_unpacking - here
    jr      $s2
    nop

start_unpacking:
    daddiu  $s4, $ra, info_entry - here

    daddiu  $s2, $ra, info_addr - here
    ld      $a0, 0($s2)

    daddiu  $s2, $ra, info_size - here
    ld      $a3, 0($s2)

    daddiu  $s2, $ra, info_key - here
    ld      $a2, 0($s2)

    daddu   $a0, $a0, $s0
    daddu   $a3, $a3, $a0

loop:
    lbu     $s1, 0($a0)
    xor     $s1, $s1, $a2
    sb      $s1, 0($a0)

    # Manual rotate right 64-bit (8-bits)
    dsll    $s2, $a2, 56
    dsrl    $a2, $a2, 8
    or      $a2, $a2, $s2

    daddiu  $a0, $a0, 1
    dsubu   $s3, $a3, $a0
    sltu    $s3, $zero, $s3
    bnez    $s3, loop
    nop

    ld      $a0, 0($sp)
    ld      $a1, 8($sp)
    ld      $a2, 16($sp)
    ld      $a3, 24($sp)
    ld      $ra, 32($sp)
    daddiu  $sp, $sp, 32

    ld      $t9, 0($s4)
    jr      $t9
    nop

# random values here, to be patched
info_start:
info_entry:     .dword 0xeeeeeeeeeeeeeeee
info_key:       .dword 0xaaaaaaaaaaaaaaaa
info_addr:      .dword 0xbbbbbbbbbbbbbbbb
info_size:      .dword 0xcccccccccccccccc
info_offset:    .dword 0xdddddddddddddddd

