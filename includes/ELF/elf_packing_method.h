#ifndef PACKING_METHOD_ELF_H
#define PACKING_METHOD_ELF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_allocation.h"
#include "packing_method.h"

int elf_pack_using_method(t_elf* elf);

#endif //PACKING_METHOD_ELF_H