#ifndef ELF_DEALLOCATION_H
#define ELF_DEALLOCATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_allocation.h"

void deallocate_elf_elf_header(t_elf* elf);
void deallocate_elf_program_header(t_elf* elf);
void deallocate_elf_sections_header(t_elf* elf);
void deallocate_elf_sections_data(t_elf* elf);
void deallocate_elf_sections_data_data(t_elf* elf);
void deallocate_elf_struct(t_elf* elf);
void deallocate_elf(t_elf* elf);

#endif //ELF_DEALLOCATION_H