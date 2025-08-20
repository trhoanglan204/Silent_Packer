#ifndef PE_SECTION_INSERTION_H
#define PE_SECTION_INSERTION_H

#include "pe_allocation.h"

int add_new_pe_section_header(t_pe* pe);
int add_new_pe_section_data(t_pe* pe);
int set_new_pe_header_values(t_pe* pe);

int pe_insert_section(t_pe* pe);

#endif //PE_SECTION_INSERTION_H