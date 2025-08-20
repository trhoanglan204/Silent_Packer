#ifndef PACK_ELF_H
#define PACK_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int pack_elf(char* file, char* file_data, size_t file_data_size, char* output);

#endif //PACK_ELF_H