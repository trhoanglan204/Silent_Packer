#include "loader_functions.h"
#include "cipher_functions.h"
#include "file_functions.h"
#include "elf_allocation.h"
#include "packer_config.h"
#include <helper.h>

uint64_t text_data_size64;
uint64_t text_entry_point64;
uint64_t cipher_key64;
uint64_t loader_offset64;
uint64_t entry_point64_addr;

uint32_t text_data_size32;
uint32_t text_entry_point32;
uint32_t cipher_key32;
uint32_t loader_offset32;
uint32_t entry_point32_addr;

char* patch_loader() {
    char* loader{};

    if (packer_config.bit == x32_ARCH) {
        loader = (char*)malloc(packer_config.loader_size);
        if (loader == NULL) {
            log_error("malloc() failure");
            return NULL;
        }
        memset(loader, 0x0, packer_config.loader_size);
        if (packer_config.arch == x32_INTEL) {
            memcpy(loader, packer_config.loader_stub, packer_config.loader_size);
            memcpy(loader + packer_config.loader_size - CIPHER_KEY_OFFSET32, &cipher_key32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - TEXT_ENTRY_POINT_OFFSET32, &text_entry_point32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - TEXT_DATA_SIZE_OFFSET32, &text_data_size32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - LOADER_OFFSET_OFFSET32, &loader_offset32, sizeof(uint32_t));
        }
        else {
            memcpy(loader, packer_config.loader_stub, packer_config.loader_size);
            memcpy(loader + packer_config.loader_size - ENTRY_POINT_ADDR_OFFSET32, &entry_point32_addr, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - CIPHER_KEY_OFFSET32, &cipher_key32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - TEXT_ENTRY_POINT_OFFSET32, &text_entry_point32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - TEXT_DATA_SIZE_OFFSET32, &text_data_size32, sizeof(uint32_t));
            memcpy(loader + packer_config.loader_size - LOADER_OFFSET_OFFSET32, &loader_offset32, sizeof(uint32_t));
        }
    }
    else {
        loader = (char*)malloc(packer_config.loader_size);
        if (loader == NULL) {
            log_error("malloc() failure");
            return NULL;
        }
        memset(loader, 0x0, packer_config.loader_size);
        if (packer_config.arch == x64_INTEL) {
            memcpy(loader, packer_config.loader_stub, packer_config.loader_size);
            memcpy(loader + packer_config.loader_size - CIPHER_KEY_OFFSET64, &cipher_key64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - TEXT_ENTRY_POINT_OFFSET64, &text_entry_point64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - TEXT_DATA_SIZE_OFFSET64, &text_data_size64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - LOADER_OFFSET_OFFSET64, &loader_offset64, sizeof(uint64_t));
        }
        else {
            memcpy(loader, packer_config.loader_stub, packer_config.loader_size);
            memcpy(loader + packer_config.loader_size - ENTRY_POINT_ADDR_OFFSET64, &entry_point64_addr, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - CIPHER_KEY_OFFSET64, &cipher_key64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - TEXT_ENTRY_POINT_OFFSET64, &text_entry_point64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - TEXT_DATA_SIZE_OFFSET64, &text_data_size64, sizeof(uint64_t));
            memcpy(loader + packer_config.loader_size - LOADER_OFFSET_OFFSET64, &loader_offset64, sizeof(uint64_t));
        }

    }
    return loader;
}