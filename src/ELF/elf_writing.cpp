#include "elf_writing.h"
#include "elf_allocation.h"
#include "file_functions.h"
#include "elf_packing_method.h"
#include "loader_functions.h"
#include "packer_config.h"
#include "all_elf_loaders_infos.h"
#include <unistd.h>
#include <helper.h>
#include <errno.h>

int write_elf(t_elf* elf, char* filename) {
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0755); // NOLINT(hicpp-signed-bitwise)
    if (fd < 0) {
        log_error("open() failure: %s", strerror(errno));
        return -1;
    }
    log_verbose("Writing ELF header ...");
    if (elf->s_type == ELF32) {
        write_to_file(fd, ((t_elf32*)elf)->elf_header, sizeof(Elf32_Ehdr));
        add_zero_padding(fd, take_byte32(((t_elf32*)elf)->elf_header->e_phoff, packer_config.endianess));

        log_verbose("Writing Program header ...");
        write_to_file(fd, ((t_elf32*)elf)->prog_header, sizeof(Elf32_Phdr) * take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess));

        log_verbose("Writing Sections data ...");
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (((t_elf32*)elf)->section_header[i].sh_type != take_byte32(SHT_NOBITS, packer_config.endianess)) {
                add_zero_padding(fd, take_byte32(((t_elf32*)elf)->section_header[i].sh_offset, packer_config.endianess));
                if (method_config.method_type == CODE_CAVE_METHOD && i == method_config.concerned_section) {
                    write_to_file(fd, ((t_elf32*)elf)->section_data[i], take_byte32(((t_elf32*)elf)->section_header[i].sh_size, packer_config.endianess) + packer_config.loader_size);
                }
                else {
                    write_to_file(fd, ((t_elf32*)elf)->section_data[i], take_byte32(((t_elf32*)elf)->section_header[i].sh_size, packer_config.endianess));
                }
            }
        }
        add_zero_padding(fd, take_byte32(((t_elf32*)elf)->elf_header->e_shoff, packer_config.endianess));

        log_verbose("Writing Sections headers ...");
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            write_to_file(fd, &(((t_elf32*)elf)->section_header[i]), sizeof(Elf32_Shdr));
        }
    }
    else {
        write_to_file(fd, ((t_elf64*)elf)->elf_header, sizeof(Elf64_Ehdr));
        add_zero_padding(fd, take_byte64(((t_elf64*)elf)->elf_header->e_phoff, packer_config.endianess));

        log_verbose("Writing Program header ...");
        write_to_file(fd, ((t_elf64*)elf)->prog_header, sizeof(Elf64_Phdr) * take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess));

        log_verbose("Writing Sections data ...");
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            if (((t_elf64*)elf)->section_header[i].sh_type != take_byte32(SHT_NOBITS, packer_config.endianess)) {
                add_zero_padding(fd, take_byte64(((t_elf64*)elf)->section_header[i].sh_offset, packer_config.endianess));
                if (method_config.method_type == CODE_CAVE_METHOD && i == method_config.concerned_section) {
                    write_to_file(fd, ((t_elf64*)elf)->section_data[i], take_byte64(((t_elf64*)elf)->section_header[i].sh_size, packer_config.endianess) + packer_config.loader_size);
                }
                else {
                    write_to_file(fd, ((t_elf64*)elf)->section_data[i], take_byte64(((t_elf64*)elf)->section_header[i].sh_size, packer_config.endianess));
                }
            }
        }
        add_zero_padding(fd, take_byte64(((t_elf64*)elf)->elf_header->e_shoff, packer_config.endianess));

        log_verbose("Writing Sections headers ...");
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            write_to_file(fd, &(((t_elf64*)elf)->section_header[i]), sizeof(Elf64_Shdr));
        }
    }
    close(fd);
    return 1;
}