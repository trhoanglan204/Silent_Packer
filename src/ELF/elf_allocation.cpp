#include "elf_allocation.h"
#include "elf_deallocation.h"
#include "file_functions.h"
#include "packer_config.h"
#include "helper.h"

int allocate_elf_elf_header(t_elf* elf, void* file_data, size_t file_data_size) {
    if (elf->s_type == ELF32) {
        if (file_data_size < sizeof(Elf32_Ehdr)) {
            log_error("Total file size is less than ELF Header size");
            return -1;
        }
        ((t_elf32*)elf)->elf_header = (Elf32_Ehdr*)malloc(sizeof(Elf32_Ehdr));
        if (((t_elf32*)elf)->elf_header == NULL) {
            deallocate_elf_elf_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_elf32*)elf)->elf_header, file_data, sizeof(Elf32_Ehdr));
        //recheck, just4sure
        if (strncmp((char*)((t_elf32*)elf)->elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
            deallocate_elf_elf_header(elf);
            log_error("Magic bytes does not match ELF bytes");
            return -1;
        }
    }
    else {
        if (file_data_size < sizeof(Elf64_Ehdr)) {
            return -1;
        }
        ((t_elf64*)elf)->elf_header = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
        if (((t_elf64*)elf)->elf_header == NULL) {
            deallocate_elf_elf_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_elf64*)elf)->elf_header, file_data, sizeof(Elf64_Ehdr));
        //recheck, just4sure
        if (strncmp((char*)((t_elf64*)elf)->elf_header->e_ident, ELFMAG, SELFMAG) != 0) {
            deallocate_elf_elf_header(elf);
            log_error("Magic bytes does not match ELF bytes");
            return -1;
        }
    }
    return 1;
}

int allocate_elf_program_header(t_elf* elf, void* file_data, size_t file_data_size) {
    if (elf->s_type == ELF32) {
        size_t elf_program_header_size = sizeof(Elf32_Phdr) * take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess);
        if (file_data_size < sizeof(Elf32_Ehdr) + elf_program_header_size) {
            log_error("Total file size is inferior to ELF Header + Program Header size");
            return -1;
        }
        ((t_elf32*)elf)->prog_header = (Elf32_Phdr*)malloc(elf_program_header_size);
        if (((t_elf32*)elf)->prog_header == NULL) {
            deallocate_elf_program_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_elf32*)elf)->prog_header, file_data + take_byte32(((t_elf32*)elf)->elf_header->e_phoff, packer_config.endianess), elf_program_header_size);
    }
    else {
        size_t elf_program_header_size = sizeof(Elf64_Phdr) * take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess);
        if (file_data_size < sizeof(Elf64_Ehdr) + elf_program_header_size) {
            log_error("Total file size is inferior to ELF Header + Program Header size");
            return -1;
        }
        ((t_elf64*)elf)->prog_header = (Elf64_Phdr*)malloc(elf_program_header_size);
        if (((t_elf64*)elf)->prog_header == NULL) {
            deallocate_elf_program_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_elf64*)elf)->prog_header, file_data + take_byte64(((t_elf64*)elf)->elf_header->e_phoff, packer_config.endianess), elf_program_header_size);
    }
    return 1;
}

int allocate_elf_sections_header(t_elf* elf, void* file_data, size_t file_data_size) {
    if (elf->s_type == ELF32) {
        size_t elf_sections_header_size = sizeof(Elf32_Shdr) * take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess);

        ((t_elf32*)elf)->section_header = (Elf32_Shdr*)malloc(elf_sections_header_size);
        if (((t_elf32*)elf)->section_header == NULL) {
            deallocate_elf_sections_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_elf32*)elf)->section_header, 0, elf_sections_header_size);

        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (file_data_size < take_byte32(((t_elf32*)elf)->elf_header->e_shoff, packer_config.endianess) + (i * sizeof(Elf32_Shdr))) {
                deallocate_elf_sections_header(elf);
                log_error("Total file size is inferior to ELF section header size");
                return -1;
            }
            memcpy(&(((t_elf32*)elf)->section_header[i]), file_data + take_byte32(((t_elf32*)elf)->elf_header->e_shoff, packer_config.endianess) + (i * sizeof(Elf32_Shdr)),
                sizeof(Elf32_Shdr));
        }
    }
    else {
        size_t elf_sections_header_size = sizeof(Elf64_Shdr) * take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess);

        ((t_elf64*)elf)->section_header = (Elf64_Shdr*)malloc(elf_sections_header_size);
        if (((t_elf64*)elf)->section_header == NULL) {
            deallocate_elf_sections_header(elf);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_elf64*)elf)->section_header, 0, elf_sections_header_size);

        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (file_data_size < take_byte64(((t_elf64*)elf)->elf_header->e_shoff, packer_config.endianess) + (i * sizeof(Elf64_Shdr))) {
                deallocate_elf_sections_header(elf);
                log_error("Total file size is inferior to ELF section header size");
                return -1;
            }
            memcpy(&(((t_elf64*)elf)->section_header[i]), file_data + take_byte64(((t_elf64*)elf)->elf_header->e_shoff, packer_config.endianess) + (i * sizeof(Elf64_Shdr)),
                sizeof(Elf64_Shdr));
        }
    }
    return 1;
}

int allocate_elf_sections_data(t_elf* elf, void* file_data, size_t file_data_size) {
    if (elf->s_type == ELF32) {
        ((t_elf32*)elf)->section_data = (char**)malloc(sizeof(char*) * take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess));
        if (((t_elf32*)elf)->section_data == NULL) {
            deallocate_elf_sections_data(elf);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_elf32*)elf)->section_data, 0, sizeof(char*) * take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess));
        size_t elf_section_data_size{};
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (((t_elf32*)elf)->section_header[i].sh_type == take_byte32(SHT_NOBITS, packer_config.endianess)) {
                ((t_elf32*)elf)->section_data[i] = NULL;
            }
            else {
                if (file_data_size < take_byte32(((t_elf32*)elf)->section_header[i].sh_offset, packer_config.endianess)) {
                    log_error("Total file size is less than section data offset");
                    return -1;
                }
                elf_section_data_size = take_byte32(((t_elf32*)elf)->section_header[i].sh_size, packer_config.endianess);
                ((t_elf32*)elf)->section_data[i] = (char*)malloc(elf_section_data_size);
                if (((t_elf32*)elf)->section_data[i] == NULL) {
                    free(((t_elf32*)elf)->section_data[i]);
                    log_error("malloc() failure");
                    return -1;
                }
                memset(((t_elf32*)elf)->section_data[i], 0, elf_section_data_size);
                memcpy(((t_elf32*)elf)->section_data[i], file_data + take_byte32(((t_elf32*)elf)->section_header[i].sh_offset, packer_config.endianess), elf_section_data_size);
            }
        }
    }
    else {
        ((t_elf64*)elf)->section_data = (char**)malloc(sizeof(char*) * take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess));
        if (((t_elf64*)elf)->section_data == NULL) {
            deallocate_elf_sections_data(elf);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_elf64*)elf)->section_data, 0, sizeof(char*) * take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess));
        size_t elf_section_data_size{};
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (((t_elf64*)elf)->section_header[i].sh_type == take_byte32(SHT_NOBITS, packer_config.endianess)) {
                ((t_elf64*)elf)->section_data[i] = NULL;
            }
            else {
                if (file_data_size < take_byte64(((t_elf64*)elf)->section_header[i].sh_offset, packer_config.endianess)) {
                    log_error("Total file size is less than section data offset");
                    return -1;
                }
                elf_section_data_size = take_byte64(((t_elf64*)elf)->section_header[i].sh_size, packer_config.endianess);
                ((t_elf64*)elf)->section_data[i] = (char*)malloc(elf_section_data_size);
                if (((t_elf64*)elf)->section_data[i] == NULL) {
                    free(((t_elf64*)elf)->section_data[i]);
                    log_error("malloc() failure");
                    return -1;
                }
                memset(((t_elf64*)elf)->section_data[i], 0, elf_section_data_size);
                memcpy(((t_elf64*)elf)->section_data[i], file_data + take_byte64(((t_elf64*)elf)->section_header[i].sh_offset, packer_config.endianess), elf_section_data_size);
            }
        }
    }
    return 1;
}

int allocate_elf(t_elf** elf, void* file_data, size_t file_data_size) {
    size_t t_elf_size;
    if (packer_config.bit == x32_ARCH)
        t_elf_size = sizeof(t_elf32);
    else
        t_elf_size = sizeof(t_elf64);
    *elf = (t_elf*)malloc(t_elf_size);
    if (*elf == NULL) {
        deallocate_elf_struct(*elf);
        return -1;
    }
    memset(*elf, 0, t_elf_size);
    t_elf type_pe{};
    if (packer_config.bit == x32_ARCH) {
        type_pe.s_type = ELF32;
        ((t_elf32*)(*elf))->type_header = type_pe;
    }
    else {
        type_pe.s_type = ELF64;
        ((t_elf64*)(*elf))->type_header = type_pe;
    }
    log_verbose("Allocating ELF Header ...");
    if (allocate_elf_elf_header(*elf, file_data, file_data_size) == -1) {
        return -1;
    }
    log_verbose("Allocating Program Header ...");
    if (allocate_elf_program_header(*elf, file_data, file_data_size) == -1) {
        deallocate_elf_elf_header(*elf);
        return -1;
    }
    log_verbose("Allocating Sections Headers ...");
    if (allocate_elf_sections_header(*elf, file_data, file_data_size) == -1) {
        deallocate_elf_elf_header(*elf);
        deallocate_elf_program_header(*elf);
        return -1;
    }
    log_verbose("Allocating Sections Data ...");
    if (allocate_elf_sections_data(*elf, file_data, file_data_size) == -1) {
        deallocate_elf_elf_header(*elf);
        deallocate_elf_program_header(*elf);
        deallocate_elf_sections_header(*elf);
        return -1;
    }
    return 1;
}