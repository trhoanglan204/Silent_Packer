#ifndef WRITE_PE_H
#define WRITE_PE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pe_allocation.h"

int write_pe(t_pe* pe, char* filename);

#endif //WRITE_PE_H