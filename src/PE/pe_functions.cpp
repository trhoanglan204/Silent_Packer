#include "pe_functions.h"
#include "pe_struct.h"
#include "pe_allocation.h"
#include "loader_functions.h"
#include "packer_config.h"
#include "all_pe_loaders_infos.h"
#include "helper.h"

#include <map>

static std::map<int, std::string> IMAGE_DIR_MAP = {
{0, "IMAGE_DIRECTORY_ENTRY_EXPORT "},
{1, "IMAGE_DIRECTORY_ENTRY_IMPORT "},
{2, "IMAGE_DIRECTORY_ENTRY_RESOURCE "},
{3, "IMAGE_DIRECTORY_ENTRY_EXCEPTION "},
{4, "IMAGE_DIRECTORY_ENTRY_SECURITY "},
{5, "IMAGE_DIRECTORY_ENTRY_BASERELOC "},
{6, "IMAGE_DIRECTORY_ENTRY_DEBUG "},
{7, "IMAGE_DIRECTORY_ENTRY_ARCHITECTURE "},
{8, "IMAGE_DIRECTORY_ENTRY_GLOBALPTR "},
{9, "IMAGE_DIRECTORY_ENTRY_TLS "},
{10, "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG "},
{11, "IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT "},
{12, "IMAGE_DIRECTORY_ENTRY_IAT "},
{13, "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT "},
{14, "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR "},
};

//code_cave
int set_new_pe_entry_to_addr(t_pe* pe, uint32_t entry_addr, int section_index, int section_size) {
    if (pe->s_type == PE32) {
        uint32_t last_entry = ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint;
        ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint = entry_addr;
        log_info("New entry point: 0x%x", ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);

        int32_t jump = last_entry - (((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint + packer_config.loader_size - packer_config.loader_infos_size);

        memcpy(((t_pe32*)pe)->section_data[section_index] + section_size + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }
    else {
        uint32_t last_entry = ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint;
        ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint = entry_addr;
        log_info("New entry point: 0x%x", ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);

        int32_t jump = last_entry - (((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint + packer_config.loader_size - packer_config.loader_infos_size);

        memcpy(((t_pe64*)pe)->section_data[section_index] + section_size + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }

    return 1;
}

//section_insertion
int set_new_pe_entry_to_section(t_pe* pe, int section_index) {
    if (pe->s_type == PE32) {
        uint32_t last_entry = ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint;
        ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint = ((t_pe32*)pe)->section_header[section_index].VirtualAddress;
        log_info("New entry point: 0x%x", ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);

        int32_t jump = last_entry - (((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint + packer_config.loader_size - packer_config.loader_infos_size);

        memcpy(((t_pe32*)pe)->section_data[section_index] + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }
    else {
        uint32_t last_entry = ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint;
        ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint = ((t_pe64*)pe)->section_header[section_index].VirtualAddress;
        log_info("New entry point: 0x%x", ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);

        int32_t jump = last_entry - (((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint + packer_config.loader_size - packer_config.loader_infos_size);

        memcpy(((t_pe64*)pe)->section_data[section_index] + packer_config.loader_size - (packer_config.loader_infos_size + 4), &jump, 4);
    }

    return 1;
}

int find_pe_text_section(t_pe* pe) {
    int index = -1;
    if (pe->s_type == PE32) {
        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (((t_pe32*)pe)->section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) { // NOLINT(hicpp-signed-bitwise)
                index = i;
            }
        }
    }
    else {
        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (((t_pe64*)pe)->section_header[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) { // NOLINT(hicpp-signed-bitwise)
                index = i;
            }
        }
    }
    return index;
}

void add_pe_section_permission(t_pe* pe, int segment_index, int permission) {
    if (pe->s_type == PE32) {
        ((t_pe32*)pe)->section_header[segment_index].Characteristics |= permission; // NOLINT(hicpp-signed-bitwise)
    }
    else {
        ((t_pe64*)pe)->section_header[segment_index].Characteristics |= permission; // NOLINT(hicpp-signed-bitwise)
    }
}

static long calc_pe_checksum(t_pe* pe) {
    size_t checksumOffset{};
    size_t fileOffset{};
    size_t file_data_size{};
    char* file_data = nullptr;
    char c = 0;

    // Reconstruct file data from the PE struct
    if (pe->s_type == PE32) {
        t_pe32* pe32 = (t_pe32*)pe;
        fileOffset = (size_t)pe32->dos_header->e_lfanew;
        checksumOffset = (char*)&pe32->pe_header->OptionalHeader.CheckSum - (char*)pe32->pe_header;


        size_t temp_offset = sizeof(IMAGE_DOS_HEADER)
            + (fileOffset - sizeof(IMAGE_DOS_HEADER))
            + sizeof(IMAGE_NT_HEADERS32)
            + (pe32->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        size_t end_offset = pe32->section_header[0].PointerToRawData;
        size_t padding_offset = end_offset - temp_offset;

        // Calculate total size: DOS header + DOS stub + PE header + sections + overlay
        file_data_size = sizeof(IMAGE_DOS_HEADER) +
            (fileOffset - sizeof(IMAGE_DOS_HEADER)) + // DOS stub
            sizeof(IMAGE_NT_HEADERS32) +
            pe32->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) +
            padding_offset;

        for (int i = 0; i < pe32->pe_header->FileHeader.NumberOfSections; i++) {
            file_data_size += pe32->section_header[i].SizeOfRawData;
        }
        file_data_size += pe32->overlay_size;

        // Allocate and reconstruct file data
        file_data = (char*)malloc(file_data_size);
        size_t current_offset = 0;

        // Copy DOS header
        memcpy(file_data, pe32->dos_header, sizeof(IMAGE_DOS_HEADER));
        current_offset += sizeof(IMAGE_DOS_HEADER);

        // Copy DOS stub
        memcpy(file_data + current_offset, pe32->dos_stub, fileOffset - sizeof(IMAGE_DOS_HEADER));
        current_offset += (fileOffset - sizeof(IMAGE_DOS_HEADER));

        // Copy PE header
        memcpy(file_data + current_offset, pe32->pe_header, sizeof(IMAGE_NT_HEADERS32));
        current_offset += sizeof(IMAGE_NT_HEADERS32);

        // Copy section headers
        memcpy(file_data + current_offset, pe32->section_header,
            pe32->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
        current_offset += (pe32->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        while (current_offset < end_offset) {
            memcpy(file_data + current_offset, &c, sizeof(c));
            current_offset += sizeof(c);
        }

        // Copy section data
        for (int i = 0; i < pe32->pe_header->FileHeader.NumberOfSections; i++) {
            memcpy(file_data + current_offset, pe32->section_data[i],
                pe32->section_header[i].SizeOfRawData);
            current_offset += pe32->section_header[i].SizeOfRawData;
        }

        // Copy overlay
        if (pe32->overlay_size > 0) {
            memcpy(file_data + current_offset, pe32->overlay, pe32->overlay_size);
        }
    }
    else {
        t_pe64* pe64 = (t_pe64*)pe;
        fileOffset = (size_t)pe64->dos_header->e_lfanew;
        checksumOffset = (char*)&pe64->pe_header->OptionalHeader.CheckSum - (char*)pe64->pe_header;

        size_t temp_offset = sizeof(IMAGE_DOS_HEADER)
            + (fileOffset - sizeof(IMAGE_DOS_HEADER))
            + sizeof(IMAGE_NT_HEADERS64)
            + (pe64->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        size_t end_offset = pe64->section_header[0].PointerToRawData;
        size_t padding_offset = end_offset - temp_offset;

        // Calculate total size: DOS header + DOS stub + PE header + sections + overlay
        file_data_size = sizeof(IMAGE_DOS_HEADER) +
            (fileOffset - sizeof(IMAGE_DOS_HEADER)) + //DOS stub
            sizeof(IMAGE_NT_HEADERS64) +
            pe64->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) +
            padding_offset;

        for (int i = 0; i < pe64->pe_header->FileHeader.NumberOfSections; i++) {
            file_data_size += pe64->section_header[i].SizeOfRawData;
        }
        file_data_size += pe64->overlay_size;

        // Allocate and reconstruct file data
        file_data = (char*)malloc(file_data_size);
        size_t current_offset = 0;

        // Copy DOS header
        memcpy(file_data, pe64->dos_header, sizeof(IMAGE_DOS_HEADER));
        current_offset += sizeof(IMAGE_DOS_HEADER);

        // Copy DOS stub
        memcpy(file_data + current_offset, pe64->dos_stub, fileOffset - sizeof(IMAGE_DOS_HEADER));
        current_offset += (fileOffset - sizeof(IMAGE_DOS_HEADER));

        // Copy PE header
        memcpy(file_data + current_offset, pe64->pe_header, sizeof(IMAGE_NT_HEADERS64));
        current_offset += sizeof(IMAGE_NT_HEADERS64);

        // Copy section headers
        memcpy(file_data + current_offset, pe64->section_header,
            pe64->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
        current_offset += (pe64->pe_header->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

        while (current_offset < end_offset) {
            memcpy(file_data + current_offset, &c, sizeof(c));
            current_offset += sizeof(c);
        }

        // Copy section data
        for (int i = 0; i < pe64->pe_header->FileHeader.NumberOfSections; i++) {
            memcpy(file_data + current_offset, pe64->section_data[i],
                pe64->section_header[i].SizeOfRawData);
            current_offset += pe64->section_header[i].SizeOfRawData;
        }

        // Copy overlay
        if (pe64->overlay_size > 0) {
            memcpy(file_data + current_offset, pe64->overlay, pe64->overlay_size);
        }
    }

    checksumOffset += fileOffset;

    // Calculate new checksum
    long long newChecksum = 0;
    const unsigned short* wordsBuff = reinterpret_cast<const unsigned short*>(file_data);
    const size_t wordsCount = file_data_size / sizeof(unsigned short);
    const size_t remainingBytes = file_data_size % sizeof(unsigned short);
    const size_t checksumBgn = checksumOffset;
    const size_t checksumEnd = checksumBgn + sizeof(uint32_t);
    const long long maxVal = ((long long)1) << 32;

    for (size_t i = 0; i < wordsCount; i++) {
        unsigned short chunk = wordsBuff[i];
        size_t bI = i * sizeof(unsigned short);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(unsigned short);
            size_t shift = (sizeof(unsigned short) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }
        newChecksum = (newChecksum & 0xffffffff) + chunk + (newChecksum >> 32);
        if (newChecksum > maxVal) {
            newChecksum = (newChecksum & 0xffffffff) + (newChecksum >> 32);
        }
    }

    if (remainingBytes > 0) {
        unsigned short chunk = 0;
        memcpy(&chunk, file_data + wordsCount * sizeof(unsigned short), remainingBytes);
        size_t bI = wordsCount * sizeof(unsigned short);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(unsigned short);
            size_t shift = (sizeof(unsigned short) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }
        newChecksum = (newChecksum & 0xffffffff) + chunk + (newChecksum >> 32);
        if (newChecksum > maxVal) {
            newChecksum = (newChecksum & 0xffffffff) + (newChecksum >> 32);
        }
    }

    newChecksum = (newChecksum & 0xffff) + (newChecksum >> 16);
    newChecksum = newChecksum + (newChecksum >> 16);
    newChecksum = newChecksum & 0xffff;
    newChecksum += file_data_size;
    free(file_data);
    return newChecksum;
}

void recalculate_pe_checksum(t_pe* pe) {
    uint32_t NewChecksum = calc_pe_checksum(pe);
    if (pe->s_type == PE32) {
        ((t_pe32*)pe)->pe_header->OptionalHeader.CheckSum = NewChecksum;
    }
    else {
        ((t_pe64*)pe)->pe_header->OptionalHeader.CheckSum = NewChecksum;
    }
    log_info("New checksum: 0x%x", NewChecksum);
    return;
}

void test_checksum(t_pe* pe) {
    uint32_t chksum = calc_pe_checksum(pe);
    uint32_t ck{};
    if (pe->s_type == PE32) {
        ck = ((t_pe32*)pe)->pe_header->OptionalHeader.CheckSum;
    }
    else {
        ck = ((t_pe64*)pe)->pe_header->OptionalHeader.CheckSum;
    }
    log_info("predicted: 0x%x", chksum);
    log_info("old: 0x%x", ck);
    return;
}

void relocate_pe_RVA(t_pe* pe, int idx) {
    uint32_t SecurityDirectory{};
    uint32_t entry{};
    if (pe->s_type == PE32) {
        entry = ((t_pe32*)pe)->section_header[idx].PointerToRawData;
        SecurityDirectory = ((t_pe32*)pe)->pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        if (SecurityDirectory != 0 && entry >= SecurityDirectory) {
            log_verbose("Fix %s to new address 0x%x", IMAGE_DIR_MAP[IMAGE_DIRECTORY_ENTRY_SECURITY].c_str(), entry + ((t_pe32*)pe)->section_header[idx].SizeOfRawData);

            ((t_pe32*)pe)->pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = entry + ((t_pe32*)pe)->section_header[idx].SizeOfRawData;
        }
    }
    else {
        entry = ((t_pe64*)pe)->section_header[idx].PointerToRawData;
        SecurityDirectory = ((t_pe64*)pe)->pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        if (SecurityDirectory != 0 && entry >= SecurityDirectory) {
            log_verbose("Fix %s to new address 0x%x", IMAGE_DIR_MAP[IMAGE_DIRECTORY_ENTRY_SECURITY].c_str(), entry + ((t_pe64*)pe)->section_header[idx].SizeOfRawData);

            ((t_pe64*)pe)->pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = entry + ((t_pe64*)pe)->section_header[idx].SizeOfRawData;
        }
    }
}

void print_pe_section_info(t_pe* pe, int section_index) {
    if (pe->s_type == PE32) {
        printf("Section name : %s\n", ((t_pe32*)pe)->section_header[section_index].Name);
        printf("VirtualSize : 0x%x\n", ((t_pe32*)pe)->section_header[section_index].Misc.VirtualSize);
        printf("SizeofRawData : 0x%x\n", ((t_pe32*)pe)->section_header[section_index].SizeOfRawData);
        printf("PointerToRawData : 0x%x\n", ((t_pe32*)pe)->section_header[section_index].PointerToRawData);
        printf("VirtualAddress : 0x%x\n", ((t_pe32*)pe)->section_header[section_index].VirtualAddress);
    }
    else {
        printf("Section name : %s\n", ((t_pe64*)pe)->section_header[section_index].Name);
        printf("VirtualSize : 0x%x\n", ((t_pe64*)pe)->section_header[section_index].Misc.VirtualSize);
        printf("SizeofRawData : 0x%x\n", ((t_pe64*)pe)->section_header[section_index].SizeOfRawData);
        printf("PointerToRawData : 0x%x\n", ((t_pe64*)pe)->section_header[section_index].PointerToRawData);
        printf("VirtualAddress : 0x%x\n", ((t_pe64*)pe)->section_header[section_index].VirtualAddress);
    }
}