#ifndef WRITE_ELF_H
#define WRITE_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ELF/elf_allocation.h"

int write_elf(t_elf* elf, char* filename);

#endif //WRITE_ELF_H