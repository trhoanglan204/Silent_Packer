#ifndef PE_ALLOCATION_H
#define PE_ALLOCATION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_struct.h"

enum PEType {
    PE32,
    PE64
};

typedef struct t_pe {
    PEType s_type;
} t_pe;

typedef struct s_pe32 {
    t_pe type_header;
    IMAGE_DOS_HEADER* dos_header;
    char* dos_stub;
    IMAGE_NT_HEADERS32* pe_header;
    IMAGE_SECTION_HEADER* section_header;
    char** section_data;
    char* overlay;
    size_t overlay_size;
} t_pe32;

typedef struct s_pe64 {
    t_pe type_header;
    IMAGE_DOS_HEADER* dos_header;
    char* dos_stub;
    IMAGE_NT_HEADERS64* pe_header;
    IMAGE_SECTION_HEADER* section_header;
    char** section_data;
    char* overlay;
    size_t overlay_size;
} t_pe64;

int allocate_pe_dos_header(t_pe* pe, void* file_data, size_t file_data_size);
int allocate_pe_dos_stub(t_pe* pe, void* file_data);
int allocate_pe_pe_header(t_pe* pe, void* file_data, size_t file_data_size);
int allocate_pe_sections_headers(t_pe* pe, void* file_data, size_t file_data_size);
int allocate_pe_sections_data(t_pe* pe, void* file_data, size_t file_data_size);
int allocate_pe_overlay(t_pe* pe, void* file_data, size_t file_data_size);

int allocate_pe(t_pe** pe, void* file_data, size_t file_data_size, int arch);

#endif //PE_ALLOCATION_H