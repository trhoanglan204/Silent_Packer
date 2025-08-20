#include "file_functions.h"
#include "elf_allocation.h"
#include "loader_functions.h"
#include "cipher_functions.h"
#include "pe_struct.h"

#include <helper.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <byteswap.h>

size_t offset = 0;

int allocate_file(char* file, void** file_data, size_t* file_data_size) {
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        log_error("open() failure: %s", strerror(errno));
        return -1;
    }
    int size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        close(fd);
        log_error("lseek() failure: %s", strerror(errno));
        return -1;
    }
    *file_data_size = size;
    *file_data = mmap(NULL, *file_data_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0); // NOLINT(hicpp-signed-bitwise)
    if (*file_data == MAP_FAILED) {
        close(fd);
        log_error("mmap() failure: %s", strerror(errno));
        return -1;
    }
    close(fd);
    return 1;
}

int check_magic_bytes(char* file_data, size_t file_data_size) {
    if (file_data_size < sizeof(Elf32_Ehdr)) {
        log_error("Invalid file size");
        return UNKNOWN_ARCH;
    }
    if (strncmp(file_data, ELFMAG, SELFMAG) == 0)
        return ELF_FILE;
    else if (strncmp(file_data, STR_DOSMAG, SSTR_DOSMAG) == 0)
        return PE_FILE;
    else
        return UNKNOWN_ARCH;
}

uint16_t take_byte16(uint16_t addr, int endianess) {
    return (endianess == ELFDATA2MSB) ? bswap_16(addr) : addr;
}
uint32_t take_byte32(uint32_t addr, int endianess) {
    return (endianess == ELFDATA2MSB) ? bswap_32(addr) : addr;
}
uint64_t take_byte64(uint64_t addr, int endianess) {
    return (endianess == ELFDATA2MSB) ? bswap_64(addr) : addr;
}

int get_elf_arch(const char* file_data, size_t file_data_size) {
    if (file_data_size < sizeof(Elf32_Ehdr)) { //at least size of 32 bit
        log_error("Invalid file size");
        return UNKNOWN_ARCH;
    }

    uint8_t elf_class = file_data[EI_CLASS];
    uint8_t elf_endianess = file_data[EI_DATA];
    if (elf_endianess != ELFDATA2LSB && elf_endianess != ELFDATA2MSB) {
        log_error("Unknown ELF data encoding");
        return UNKNOWN_ARCH;
    }
    uint16_t machine{};

    if (elf_class == ELFCLASS32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)file_data;
        machine = take_byte16(ehdr->e_machine, elf_endianess);
        if (machine == EM_386) return x32_INTEL;
        if (machine == EM_ARM || machine == EM_MIPS) {
            entry_point32_addr = ehdr->e_entry;
            log_verbose("Entry point address: 0x%x", take_byte32(entry_point32_addr, elf_endianess));

            if (machine == EM_ARM)
                return  (elf_endianess == ELFDATA2LSB) ? x32_ARM : x32_ARM_BE;
            else
                return (elf_endianess == ELFDATA2LSB) ? x32_MIPS : x32_MIPS_BE;
        }
    }
    if (elf_class == ELFCLASS64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        machine = take_byte16(ehdr->e_machine, elf_endianess);
        if (machine == EM_X86_64) return x64_INTEL;
        if (machine == EM_AARCH64 || machine == EM_MIPS) {
            entry_point64_addr = ehdr->e_entry;
            log_verbose("Entry point address: 0x%lx", take_byte64(entry_point64_addr, elf_endianess));

            if (machine == EM_AARCH64)
                return (elf_endianess == ELFDATA2LSB) ? x64_ARM : x64_ARM_BE;
            else
                return (elf_endianess == ELFDATA2LSB) ? x64_MIPS : x64_MIPS_BE;
        }
    }
    return UNKNOWN_ARCH;
}

uint16_t get_elf_type(const char* file_data) {
    uint8_t elf_class = file_data[EI_CLASS];
    uint8_t elf_endianess = file_data[EI_DATA];
    if (elf_class == ELFCLASS32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)file_data;
        return take_byte16(ehdr->e_type, elf_endianess);
    }
    else {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        return take_byte16(ehdr->e_type, elf_endianess);
    }
}

bool is_stripped(const char* file_data) {
    uint8_t elf_class = file_data[EI_CLASS];
    uint8_t elf_endianess = file_data[EI_DATA];
    if (elf_class == ELFCLASS32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)file_data;
        Elf32_Shdr* shdrs = (Elf32_Shdr*)(file_data + take_byte32(ehdr->e_shoff, elf_endianess));
        for (int i = 0; i < take_byte16(ehdr->e_shnum, elf_endianess); ++i) {
            if (shdrs[i].sh_type == take_byte32(SHT_SYMTAB, elf_endianess)) {
                return false; //not stripped
            }
        }
    }
    else {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        Elf64_Shdr* shdrs = (Elf64_Shdr*)(file_data + take_byte64(ehdr->e_shoff, elf_endianess));
        for (int i = 0; i < take_byte16(ehdr->e_shnum, elf_endianess); ++i) {
            if (shdrs[i].sh_type == take_byte32(SHT_SYMTAB, elf_endianess)) {
                return false; //not stripped
            }
        }
    }
    return true; //stripped
}

bool get_elf_interp(const char* file_data) {
    uint8_t elf_class = file_data[EI_CLASS];
    uint8_t elf_endianess = file_data[EI_DATA];
    if (elf_class == ELFCLASS32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)file_data;
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            Elf32_Phdr* phdr = (Elf32_Phdr*)(file_data + take_byte32(ehdr->e_phoff, elf_endianess) + i * sizeof(Elf32_Phdr));
            if (phdr->p_type == take_byte32(PT_INTERP, elf_endianess)) return true;
        }
    }
    else {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        for (int i = 0; i < ehdr->e_phnum; ++i) {
            Elf64_Phdr* phdr = (Elf64_Phdr*)(file_data + take_byte64(ehdr->e_phoff, elf_endianess) + i * sizeof(Elf64_Phdr));
            if (phdr->p_type == take_byte32(PT_INTERP, elf_endianess)) return true;
        }
    }
    return false;
}

const char* get_interp_path(const char* file_data) {
    uint8_t elf_class = file_data[EI_CLASS];
    uint8_t elf_endianess = file_data[EI_DATA];
    if (elf_class == ELFCLASS32) {
        Elf32_Ehdr* ehdr = (Elf32_Ehdr*)file_data;
        for (int i = 0; i < take_byte16(ehdr->e_phnum, elf_endianess); ++i) {
            Elf32_Phdr* phdr = (Elf32_Phdr*)(file_data + take_byte32(ehdr->e_phoff, elf_endianess) + i * sizeof(Elf32_Phdr));
            if (phdr->p_type == take_byte32(PT_INTERP, elf_endianess))
                return file_data + take_byte32(phdr->p_offset, elf_endianess);
        }
    }
    else {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        for (int i = 0; i < take_byte16(ehdr->e_phnum, elf_endianess); ++i) {
            Elf64_Phdr* phdr = (Elf64_Phdr*)(file_data + take_byte64(ehdr->e_phoff, elf_endianess) + i * sizeof(Elf64_Phdr));
            if (phdr->p_type == take_byte32(PT_INTERP, elf_endianess))
                return file_data + take_byte64(phdr->p_offset, elf_endianess);
        }
    }
    return nullptr;
}


int get_pe_arch(const char* file_data, size_t file_data_size) {
    if (file_data_size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32)) { //at least file 32 bit
        log_error("Invalid file size");
        return UNKNOWN_ARCH;
    }

    const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) { // 'MZ' recheck, just4sure
        log_error("Invalid DOS signature");
        return UNKNOWN_ARCH;
    }

    if ((dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER)) <= 0) {
        log_error("Invalid DOS stub size");
        return UNKNOWN_ARCH;
    }

    if (dos_header->e_lfanew > file_data_size) {
        log_error("e_lfanew points to an offset beyond the file size");
        return UNKNOWN_ARCH;
    }

    const IMAGE_NT_HEADERS32* nt_header = (const IMAGE_NT_HEADERS32*)(file_data + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {  // 'PE\0\0'
        log_error("Invalid PE signature");
        return UNKNOWN_ARCH;
    }

    //same offset for 32 and 64
    uint16_t machine = nt_header->FileHeader.Machine;
    uint16_t magic = nt_header->OptionalHeader.Magic;

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (machine == IMAGE_FILE_MACHINE_I386) return x32_INTEL;
        if (machine == IMAGE_FILE_MACHINE_ARM) return x32_ARM;
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (machine == IMAGE_FILE_MACHINE_AMD64) return x64_INTEL;
        if (machine == IMAGE_FILE_MACHINE_ARM64) return x64_ARM;
    }

    return UNKNOWN_ARCH;
}

bool isDLL(const char* file_data, int bits) {
    const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;
    if (bits == x32_ARCH) {
        const IMAGE_NT_HEADERS32* nt_header32 = (const IMAGE_NT_HEADERS32*)(file_data + dos_header->e_lfanew);
        if (nt_header32->FileHeader.Characteristics & IMAGE_FILE_DLL) return true;
    }
    else {
        const IMAGE_NT_HEADERS64* nt_header64 = (const IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
        if (nt_header64->FileHeader.Characteristics & IMAGE_FILE_DLL) return true;
    }
    return false;
}

bool isExecutable(const char* file_data, int bits) {
    const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;
    if (bits == x32_ARCH) {
        const IMAGE_NT_HEADERS32* nt_header32 = (const IMAGE_NT_HEADERS32*)(file_data + dos_header->e_lfanew);
        if (nt_header32->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) return true;
    }
    else {
        const IMAGE_NT_HEADERS64* nt_header64 = (const IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
        if (nt_header64->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) return true;
    }
    return false;
}

int get_pe_subsystem(const char* file_data, int bits) {
    const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;
    if (bits == x32_ARCH) {
        const IMAGE_NT_HEADERS32* nt_header32 = (const IMAGE_NT_HEADERS32*)(file_data + dos_header->e_lfanew);
        const IMAGE_OPTIONAL_HEADER32* opt32 = &nt_header32->OptionalHeader;
        return opt32->Subsystem;
    }
    else {
        const IMAGE_NT_HEADERS64* nt_header64 = (const IMAGE_NT_HEADERS64*)(file_data + dos_header->e_lfanew);
        const IMAGE_OPTIONAL_HEADER64* opt64 = &nt_header64->OptionalHeader;
        return opt64->Subsystem;
    }
}

int write_to_file(int fd, void* data, size_t data_size) {
    size_t n_bytes{};
    if ((n_bytes = write(fd, data, data_size)) != data_size) {
        log_error("write() failure: %s", strerror(errno));
        return -1;
    }
    offset += n_bytes;
    return 1;
}

void add_zero_padding(int fd, size_t end_offset) {
    char c = 0;
    while (offset < end_offset) {
        write_to_file(fd, &c, sizeof(c));
    }
}
