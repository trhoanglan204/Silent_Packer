#ifndef PACKING_METHOD_H
#define PACKING_METHOD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTION_INSERTION_METHOD 1
#define CODE_CAVE_METHOD 2

struct method_config {
    int method_type;
    int concerned_section;
};

extern struct method_config method_config;

#endif //PACKING_METHOD_H