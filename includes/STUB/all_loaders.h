#ifndef ALL_LOADERS_H
#define ALL_LOADERS_H

#include "all_elf_loaders.h"

#include "all_pe_loaders.h"

#endif //ALL_LOADERS_H

/*
compile shellcode:

# x86-64 linux | pe:
nasm -f elf64 -o shellcode.o amd64_xor_linux_elf_loader.asm
ld -s -o shellcode shellcode.o

# i386 linux | pe:
nasm -f elf32 -o shellcode.o i386_xor_linux_elf_loader.asm
ld -m elf_i386 -o shellcode shellcode.o

# arm el
arm-linux-gnueabi-as -o shellcode.o shellcode.s
arm-linux-gnueabi-ld -o shellcode shellcode.o

# arm be
arm-linux-gnueabi-as -EB -o shellcode.o shellcode.s
arm-linux-gnueabi-ld -EB -o shellcode shellcode.o

# aarch el
aarch64-linux-gnu-as -o shellcode.o shellcode.s
aarch64-linux-gnu-ld -o shellcode shellcode.o

# aarch be
aarch64-linux-gnu-as -EB -o shellcode.o shellcode.s
aarch64-linux-gnu-as -EB -o shellcode.o shellcode.s

# mips32 be
mips-linux-gnu-as -o shellcode.o shellcode.s
mips-linux-gnu-as -o shellcode.o shellcode.s

# mips32 el
mips-linux-gnu-as -EL -o shellcode.o shellcode.s
mips64-linux-gnu-as -EL -o shellcode.o shellcode.s

# mips64 be
mips64-linux-gnuabi64-as -o shellcode.o shellcode.s
mips64-linux-gnuabi64-as -o shellcode.o shellcode.s

# mips64 el
mips64-linux-gnuabi64-as -EL -o shellcode.o shellcode.s
mips64-linux-gnuabi64-as -EL -o shellcode.o shellcode.s

# soft or hard float just different about handling float pointer, no need care into shellcode
# mips prefer big-endian

*/
