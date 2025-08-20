#include "elf_packing.h"
#include "elf_allocation.h"
#include "elf_deallocation.h"
#include "file_functions.h"
#include "elf_encryption.h"
#include "elf_writing.h"
#include "elf_packing_method.h"
#include "packer_config.h"
#include <sys/mman.h>
#include <helper.h>
#include <string>

/*
 * Basic ELF structure
 *
 * -----------
 * ELF Header
 * -----------
 * Program header table
 * -----------
 * [section_data]
 * .text
 * .rodata
 * .shstrtab (string table section names)
 * [...]
 * -----------
 * Section header table containing multiple section headers
 * .text header
 * -----------
 *
*/

static void log_arch(s_packer_config& packer, char* file_name, char* file_data) {
    uint16_t type = get_elf_type(file_data);
    bool interp = get_elf_interp(file_data);

    const char* endian_str[] = { "", "LSB", "MSB" };
    const char* display_stripped = is_stripped(file_data) ? "stripped" : "with debug_info, not stripped";
    const char* display_linked = interp ? "dynamic linked" : "static linked";
    const char* display_type = "";
    const char* display_interp = "";
    const char* display_arch = "";
    const char* display_bits = "";

    if (type == ET_EXEC) {
        display_type = "executable";
        if (interp) display_interp = get_interp_path(file_data);
    }
    else if (type == ET_DYN) {
        display_type = interp ? "pie executable" : "shared object";
        if (interp) display_interp = get_interp_path(file_data);
    }

    switch (packer.bit) {
    case x32_ARCH:
        display_bits = "32-bit";
        break;
    case x64_ARCH:
        display_bits = "64-bit";
        break;
    }
    switch (packer.arch) {
    case x32_INTEL:
        display_arch = "Intel 80386";
        break;
    case x64_INTEL:
        display_arch = "x86-64";
        break;
    case x32_ARM:
    case x32_ARM_BE:
        display_arch = "ARM";
        break;
    case x64_ARM:
    case x64_ARM_BE:
        display_arch = "ARM aarch64";
        break;
    case x32_MIPS:
    case x64_MIPS:
        display_arch = "MIPS";
        break;
    }
    std::string display = std::string(file_name) + ": ELF " +
        display_bits + " " +
        endian_str[packer.endianess] + " " +
        display_type + ", " +
        display_arch + ", " +
        display_linked + ", ";

    if (display_interp != nullptr && *display_interp != '\0') {
        display += "interpreter " + std::string(display_interp) + ", ";
    }

    display += display_stripped;
    log_verbose(display.c_str());
}

int pack_elf(char* file, char* file_data, size_t file_data_size, char* output) {
    log_arch(packer_config, file, file_data);
    log_info("Allocating ELF in memory ...");

    t_elf* elf = NULL;
    if (allocate_elf(&elf, file_data, file_data_size) == -1) {
        munmap(file_data, file_data_size);
        log_error("Error during ELF allocation");
        return -1;
    }

    // De-allocate mapped file as we don't need it anymore
    munmap(file_data, file_data_size);

    log_info("Encrypting .text section ...");
    if (encrypt_elf(elf) == -1) {
        deallocate_elf(elf);
        log_error("Error during ELF encryption");
        return -1;
    }

    log_info("Packing using specified method ...");
    if (elf_pack_using_method(elf) == -1) {
        deallocate_elf(elf);
        log_error("Error during ELF packing");
        return -1;
    }

    log_info("Writing Packed ELF to file ...");
    if (write_elf(elf, output) == -1) {
        deallocate_elf(elf);
        log_error("Error during new ELF writing");
        return -1;
    }
    log_success("File %s packed into %s !", file, output);
    deallocate_elf(elf);
    return 1;
}