#ifndef FILE_FUNCTIONS_H
#define FILE_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define ELF_FILE        1
#define PE_FILE			2

#define x32_ARCH		32
#define x64_ARCH		64

#define x32_INTEL		1 
#define x64_INTEL		2
#define x32_ARM			3
#define x32_ARM_BE		30
#define x64_ARM			4
#define x64_ARM_BE		40
#define x32_MIPS		9
#define x32_MIPS_BE		10
#define x64_MIPS		11
#define x64_MIPS_BE		12
#define UNKNOWN_ARCH    (-1)

int allocate_file(char* file, void** file_data, size_t* file_data_size);
int write_to_file(int fd, void* data, size_t data_size);
int dump_to_file(char* filename, char* data, size_t data_size);
void add_zero_padding(int fd, size_t end_offset);
int check_magic_bytes(char* file_data, size_t file_data_size);

int get_elf_arch(const char* file_data, size_t file_data_size);
uint16_t get_elf_type(const char* file_data);
bool get_elf_interp(const char* file_data);
bool is_stripped(const char* file_data);
const char* get_interp_path(const char* file_data);

int get_pe_arch(const char* file_data, size_t file_data_size);
bool isDLL(const char* file_data, int bits);
bool isExecutable(const char* file_data, int bits);
int get_pe_subsystem(const char* file_data, int bits);

uint16_t take_byte16(uint16_t addr, int endianess);
uint32_t take_byte32(uint32_t addr, int endianess);
uint64_t take_byte64(uint64_t addr, int endianess);

#endif //FILE_FUNCTIONS_H