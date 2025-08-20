#include "packer_config.h"
#include "all_loaders.h"
#include "cipher_functions.h"
#include "file_functions.h"
#include "elf_allocation.h"
#include "pe_allocation.h"
#include <helper.h>

struct s_packer_config packer_config;

int fill_packer_config(const char* packing_method, int arch, int filetype, std::string file_name) {
    strncpy(packer_config.packing_method, packing_method, MAX_PACKING_METHOD_LENGTH);
    packer_config.arch = arch;

    if (filetype == ELF_FILE) {
        if (arch == x32_INTEL) {
            packer_config.loader_infos_size = I386_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = I386_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(i386_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x64_INTEL) {
            packer_config.loader_infos_size = AMD64_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = AMD64_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(amd64_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x32_ARM) {
            packer_config.loader_infos_size = ARM_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = ARM_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(arm_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x32_ARM_BE) {
            packer_config.loader_infos_size = ARM_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = ARM_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(arm_be_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2MSB;
        }
        else if (arch == x64_ARM) {
            packer_config.loader_infos_size = AARCH64_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = AARCH64_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(aarch64_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x64_ARM_BE) {
            packer_config.loader_infos_size = AARCH64_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = AARCH64_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(aarch64_be_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2MSB;
        }
        else if (arch == x32_MIPS) {
            packer_config.loader_infos_size = MIPS32_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = MIPS32_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(mips32_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x32_MIPS_BE) {
            packer_config.loader_infos_size = MIPS32_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = MIPS32_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(mips32_be_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2MSB;
        }
        else if (arch == x64_MIPS) {
            packer_config.loader_infos_size = MIPS64_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = MIPS64_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(mips64_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x64_MIPS_BE) {
            packer_config.loader_infos_size = MIPS64_XOR_LINUX_ELF_LOADER_INFOS_SIZE;
            packer_config.loader_size = MIPS64_XOR_LINUX_ELF_LOADER_SIZE;
            packer_config.loader_stub = &(mips64_be_xor_linux_elf_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2MSB;
        }
        else {
            log_error("Unknown arch");
            return -1;
        }
    }
    else if (filetype == PE_FILE) {
        if (arch == x32_INTEL) {
            packer_config.loader_infos_size = I386_XOR_WIN_PE_LOADER_INFOS_SIZE;
            packer_config.loader_size = I386_XOR_WIN_PE_LOADER_SIZE;
            packer_config.loader_stub = &(i386_xor_win_pe_loader_stub[0]);
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x64_INTEL) {
            packer_config.loader_infos_size = AMD64_XOR_WIN_PE_LOADER_INFOS_SIZE;
            packer_config.loader_size = AMD64_XOR_WIN_PE_LOADER_SIZE;
            packer_config.loader_stub = &(amd64_xor_win_pe_loader_stub[0]);
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x32_ARM) {
            //TODO: implement later
            packer_config.bit = x32_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else if (arch == x64_ARM) {
            //TODO: implement later
            packer_config.bit = x64_ARCH;
            packer_config.endianess = ELFDATA2LSB;
        }
        else {
            log_error("Unknown arch");
            return -1;
        }
    }
    else {
        log_error("Unknown file type");
        return -1;
    }

    return 1;
}


