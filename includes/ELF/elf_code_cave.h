#ifndef CODE_CAVE_H
#define CODE_CAVE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_allocation.h"

int find_elf_code_cave_index(t_elf* elf);
int set_new_elf_cave_segment_values(t_elf* elf, int segment_index);
int elf_cave_insert_loader32(t_elf* elf, int section_index, uint32_t old_section_size);
int elf_cave_insert_loader64(t_elf* elf, int section_index, uint64_t old_section_size);

int elf_code_cave_injection(t_elf* elf);

#endif //CODE_CAVE_H