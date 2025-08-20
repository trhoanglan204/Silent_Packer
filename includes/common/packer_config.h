#ifndef PACKER_CONFIG_H
#define PACKER_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string>

#define MAX_CIPHER_LENGTH 20
#define MAX_PACKING_METHOD_LENGTH 40

struct s_packer_config {
    int bit;
    int arch;
    int endianess;
    char packing_method[MAX_PACKING_METHOD_LENGTH];
    size_t cipher_key_offset;
    size_t loader_size;
    size_t loader_infos_size;
    unsigned char* loader_stub;
};

extern struct s_packer_config packer_config;

int fill_packer_config(const char* packing_method, int arch, int filetype, std::string file_name);

#endif //PACKER_CONFIG_H