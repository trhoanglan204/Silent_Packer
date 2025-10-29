#include "elf_functions.h"
#include "elf_allocation.h"
#include "loader_functions.h"
#include "packer_config.h"
#include "all_elf_loaders_infos.h"
#include <file_functions.h>
#include "helper.h"

int set_new_elf_entry_to_section(t_elf* elf, int section_index) {
    if (elf->s_type == ELF32) {
        Elf32_Addr last_entry = take_byte32(((t_elf32*)elf)->elf_header->e_entry, packer_config.endianess);
        ((t_elf32*)elf)->elf_header->e_entry = ((t_elf32*)elf)->section_header[section_index].sh_addr;
        log_info("New entry point: 0x%x", take_byte32(((t_elf32*)elf)->elf_header->e_entry, packer_config.endianess));
        if (packer_config.arch = x32_INTEL) {
            int32_t jump = last_entry - (((t_elf32*)elf)->elf_header->e_entry + packer_config.loader_size - packer_config.loader_infos_size);
            memcpy(((t_elf32*)elf)->section_data[section_index] + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
        }
    }
    else {
        Elf64_Addr last_entry = take_byte64(((t_elf64*)elf)->elf_header->e_entry, packer_config.endianess);
        log_info("New entry point: 0x%lx", take_byte64(((t_elf64*)elf)->elf_header->e_entry, packer_config.endianess));
        ((t_elf64*)elf)->elf_header->e_entry = ((t_elf64*)elf)->section_header[section_index].sh_addr;
        if (packer_config.arch = x64_INTEL) {
            int32_t jump = last_entry - (((t_elf64*)elf)->elf_header->e_entry + packer_config.loader_size - packer_config.loader_infos_size);
            memcpy(((t_elf64*)elf)->section_data[section_index] + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
        }
    }
    return 1;
}

int set_new_elf_entry_to_addr32(t_elf* elf, uint32_t entry_address, int section_index, int section_size) {
    Elf32_Addr last_entry = take_byte32(((t_elf32*)elf)->elf_header->e_entry, packer_config.endianess);
    ((t_elf32*)elf)->elf_header->e_entry = take_byte32(entry_address, packer_config.endianess);
    if (packer_config.arch = x32_INTEL) {
        int32_t jump = last_entry - (((t_elf32*)elf)->elf_header->e_entry + packer_config.loader_size - packer_config.loader_infos_size);
        memcpy(((t_elf32*)elf)->section_data[section_index] + section_size + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }
    return 1;
}

int set_new_elf_entry_to_addr64(t_elf* elf, uint64_t entry_address, int section_index, int section_size) {
    Elf64_Addr last_entry = ((t_elf64*)elf)->elf_header->e_entry;
    ((t_elf64*)elf)->elf_header->e_entry = take_byte64(entry_address, packer_config.endianess);
    if (packer_config.arch = x64_INTEL) {
        int32_t jump = last_entry - (((t_elf64*)elf)->elf_header->e_entry + packer_config.loader_size - packer_config.loader_infos_size);
        memcpy(((t_elf64*)elf)->section_data[section_index] + section_size + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }
    return 1;
}

int find_last_elf_segment_of_type(t_elf* elf, uint32_t p_type) {
    int index = -1;
    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (((t_elf32*)elf)->prog_header[i].p_type == p_type) {
                index = i;
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (((t_elf64*)elf)->prog_header[i].p_type == p_type) {
                index = i;
            }
        }
    }
    return index;
}

// Find last section from specified segment index
int find_last_elf_section_from_segment(t_elf* elf, int segment_index) {
    int index = -1;
    if (elf->s_type == ELF32) {
        Elf32_Phdr* program_header = ((t_elf32*)elf)->prog_header + segment_index;
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            Elf32_Shdr* section_header = ((t_elf32*)elf)->section_header + i;
            if (take_byte32(section_header->sh_addr, packer_config.endianess) >= take_byte32(program_header->p_vaddr, packer_config.endianess)
                && take_byte32(section_header->sh_addr, packer_config.endianess) < take_byte32(program_header->p_vaddr, packer_config.endianess) + take_byte32(program_header->p_memsz, packer_config.endianess)
                ) {
                index = i;
            }
        }
    }
    else {
        Elf64_Phdr* program_header = ((t_elf64*)elf)->prog_header + segment_index;
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            Elf64_Shdr* section_header = ((t_elf64*)elf)->section_header + i;
            if (take_byte64(section_header->sh_addr, packer_config.endianess) >= take_byte64(program_header->p_vaddr, packer_config.endianess)
                && take_byte64(section_header->sh_addr, packer_config.endianess) < take_byte64(program_header->p_vaddr, packer_config.endianess) + take_byte64(program_header->p_memsz, packer_config.endianess)
                ) {
                index = i;
            }
        }
    }
    return index;
}

int find_elf_text_segment(t_elf* elf) {
    int index = -1;
    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (take_byte32(((t_elf32*)elf)->prog_header[i].p_type, packer_config.endianess) == PT_LOAD
                && take_byte32(((t_elf32*)elf)->elf_header->e_entry, packer_config.endianess) < (take_byte32(((t_elf32*)elf)->prog_header[i].p_vaddr, packer_config.endianess) + take_byte32(((t_elf32*)elf)->prog_header[i].p_filesz, packer_config.endianess))
                && take_byte32(((t_elf32*)elf)->elf_header->e_entry, packer_config.endianess) > take_byte32(((t_elf32*)elf)->prog_header[i].p_vaddr, packer_config.endianess)) {
                index = i;
                break;
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (take_byte32(((t_elf64*)elf)->prog_header[i].p_type, packer_config.endianess) == PT_LOAD
                && take_byte64(((t_elf64*)elf)->elf_header->e_entry, packer_config.endianess) < (take_byte64(((t_elf64*)elf)->prog_header[i].p_vaddr, packer_config.endianess) + take_byte64(((t_elf64*)elf)->prog_header[i].p_filesz, packer_config.endianess))
                && take_byte64(((t_elf64*)elf)->elf_header->e_entry, packer_config.endianess) > take_byte64(((t_elf64*)elf)->prog_header[i].p_vaddr, packer_config.endianess)) {
                index = i;
                break;
            }
        }
    }
    return index;
}

int find_elf_segment_index_of_section(t_elf* elf, int section_index) {
    int index = -1;

    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (take_byte32(((t_elf32*)elf)->prog_header[i].p_offset, packer_config.endianess) <= take_byte32(((t_elf32*)elf)->section_header[section_index].sh_offset, packer_config.endianess)) {
                index = i;
            }
            else {
                if (index == -1)
                    index = 0;
                break;
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (take_byte64(((t_elf64*)elf)->prog_header[i].p_offset, packer_config.endianess) <= take_byte64(((t_elf64*)elf)->section_header[section_index].sh_offset, packer_config.endianess)) {
                index = i;
            }
            else {
                if (index == -1)
                    index = 0;
                break;
            }
        }
    }
    return index;
}

char* find_elf_section_name(t_elf* elf, int index) {
    if (elf->s_type == ELF32) {
        int section_string_table_index = take_byte16(((t_elf32*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        return ((char*)(((t_elf32*)elf)->section_data[section_string_table_index] + take_byte32(((t_elf32*)elf)->section_header[index].sh_name, packer_config.endianess)));
    }
    else {
        int section_string_table_index = take_byte16(((t_elf64*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        return ((char*)(((t_elf64*)elf)->section_data[section_string_table_index] + take_byte32(((t_elf64*)elf)->section_header[index].sh_name, packer_config.endianess)));
    }
}

int find_elf_section_index(t_elf* elf, char* section_name) {
    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            char* s_name = find_elf_section_name(elf, i);
            if (strcmp(section_name, s_name) == 0) {
                return i;
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            char* s_name = find_elf_section_name(elf, i);
            if (strcmp(section_name, s_name) == 0) {
                return i;
            }
        }
    }
    return -1;
}

void add_elf_segment_permission(t_elf* elf, int segment_index, int permission) {
    if (elf->s_type == ELF32)
        ((t_elf32*)elf)->prog_header[segment_index].p_flags |= take_byte32(permission, packer_config.endianess); // NOLINT(hicpp-signed-bitwise)
    else
        ((t_elf64*)elf)->prog_header[segment_index].p_flags |= take_byte32(permission, packer_config.endianess); // NOLINT(hicpp-signed-bitwise)
}