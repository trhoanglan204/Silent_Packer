#ifndef PE_FUNCTIONS_H
#define PE_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_allocation.h"

int set_new_pe_entry_to_section(t_pe* pe, int section_index);
int set_new_pe_entry_to_addr(t_pe* pe, uint32_t entry_addr, int section_index, int section_size);

int find_pe_text_section(t_pe* pe);
void add_pe_section_permission(t_pe* pe, int segment_index, int permission);
void recalculate_pe_checksum(t_pe* pe);
void relocate_pe_RVA(t_pe* pe, int idx);

void test_checksum(t_pe* pe);
void print_pe_section_info(t_pe* pe, int section_index);

#endif //PE_FUNCTIONS_H