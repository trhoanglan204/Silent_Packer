#ifndef LOADER_FUNCTIONS_H
#define LOADER_FUNCTIONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ENTRY_POINT_ADDR_OFFSET32	20
#define CIPHER_KEY_OFFSET32         16
#define TEXT_ENTRY_POINT_OFFSET32   12
#define TEXT_DATA_SIZE_OFFSET32     8
#define LOADER_OFFSET_OFFSET32      4

#define ENTRY_POINT_ADDR_OFFSET64	40
#define CIPHER_KEY_OFFSET64         32
#define TEXT_ENTRY_POINT_OFFSET64   24
#define TEXT_DATA_SIZE_OFFSET64     16
#define LOADER_OFFSET_OFFSET64      8

extern uint32_t text_data_size32;
extern uint32_t text_entry_point32;
extern uint32_t cipher_key32;
extern uint32_t loader_offset32;
extern uint32_t entry_point32_addr;

extern uint64_t text_data_size64;
extern uint64_t text_entry_point64;
extern uint64_t cipher_key64;
extern uint64_t loader_offset64;
extern uint64_t entry_point64_addr;

char* patch_loader();

#endif //LOADER_FUNCTIONS_H