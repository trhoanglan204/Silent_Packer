#include "elf_encryption.h"
#include "cipher_functions.h"
#include "elf_allocation.h"
#include "elf_functions.h"
#include "loader_functions.h"
#include "packer_config.h"
#include "file_functions.h"
#include "helper.h"

int encrypt_elf(t_elf* elf) {
    int text_section_index = find_elf_section_index(elf, ".text");
    if (text_section_index == -1) {
        log_error("Couldn't find .text section in the ELF binary");
        return -1;
    }

    log_verbose("Got .text section index : %d", text_section_index);
    char* text_data{};

    if (elf->s_type == ELF32) {
        text_data = ((t_elf32*)elf)->section_data[text_section_index];
        text_data_size32 = ((t_elf32*)elf)->section_header[text_section_index].sh_size;
        text_entry_point32 = ((t_elf32*)elf)->section_header[text_section_index].sh_addr;
        log_verbose("Generating random key ...");
        cipher_key32 = generate_random_key32();
        uint32_t temp_key = take_byte32(cipher_key32, packer_config.endianess);

        log_info("Random key : 0x%x", cipher_key32);
        if (packer_config.endianess == ELFDATA2MSB) {
            log_info("Random key (big-endian) : 0x%x", temp_key);
        }
        xor_encrypt32(text_data, take_byte32(text_data_size32, packer_config.endianess), temp_key);
    }
    else {
        text_data = ((t_elf64*)elf)->section_data[text_section_index];
        text_data_size64 = ((t_elf64*)elf)->section_header[text_section_index].sh_size;
        text_entry_point64 = ((t_elf64*)elf)->section_header[text_section_index].sh_addr;
        log_verbose("Generating random key ...");
        cipher_key64 = generate_random_key64();
        uint64_t temp_key = take_byte64(cipher_key64, packer_config.endianess);

        log_info("Random key : 0x%lx", cipher_key64);
        if (packer_config.endianess == ELFDATA2MSB) {
            log_info("Random key (big-endian) : 0x%lx", temp_key);
        }
        xor_encrypt64(text_data, take_byte64(text_data_size64, packer_config.endianess), temp_key);
    }
    return 1;
}