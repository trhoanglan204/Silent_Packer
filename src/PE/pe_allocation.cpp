#include "pe_allocation.h"
#include "pe_deallocation.h"
#include "file_functions.h"
#include "packer_config.h"
#include "helper.h"

int allocate_pe_dos_header(t_pe* pe, void* file_data, size_t file_data_size) {
    if (file_data_size < sizeof(IMAGE_DOS_HEADER)) { // recheck, just4sure
        log_error("Total file size is less than DOS Header size");
        return -1;
    }

    if (pe->s_type == PE32) {
        ((t_pe32*)pe)->dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));

        if (((t_pe32*)pe)->dos_header == NULL) {
            deallocate_pe_dos_header(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe32*)pe)->dos_header, file_data, sizeof(IMAGE_DOS_HEADER));

        //recheck, just4sure
        if (((t_pe32*)pe)->dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            deallocate_pe_dos_header(pe);
            log_error("Magic bytes do not match PE file");
            return -1;
        }
    }
    else {
        ((t_pe64*)pe)->dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));

        if (((t_pe64*)pe)->dos_header == NULL) {
            deallocate_pe_dos_header(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe64*)pe)->dos_header, file_data, sizeof(IMAGE_DOS_HEADER));

        //recheck, just4sure
        if (((t_pe64*)pe)->dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            deallocate_pe_dos_header(pe);
            log_error("Magic bytes do not match PE file");
            return -1;
        }
    }

    return 1;
}

int allocate_pe_dos_stub(t_pe* pe, void* file_data) {
    const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;

    size_t dos_stub_size = dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER);

    if (pe->s_type == PE32) {
        ((t_pe32*)pe)->dos_stub = (char*)malloc(dos_stub_size);
        if (((t_pe32*)pe)->dos_stub == NULL) {
            deallocate_pe_dos_stub(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe32*)pe)->dos_stub, file_data + sizeof(IMAGE_DOS_HEADER), dos_stub_size);
    }
    else {
        ((t_pe64*)pe)->dos_stub = (char*)malloc(dos_stub_size);
        if (((t_pe64*)pe)->dos_stub == NULL) {
            deallocate_pe_dos_stub(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe64*)pe)->dos_stub, file_data + sizeof(IMAGE_DOS_HEADER), dos_stub_size);
    }

    return 1;
}

int allocate_pe_pe_header(t_pe* pe, void* file_data, size_t file_data_size) {
    if (pe->s_type == PE32) {
        if (file_data_size < sizeof(IMAGE_NT_HEADERS32)) {
            log_error("Total file size is less than PE Header size");
            return -1;
        }

        ((t_pe32*)pe)->pe_header = (IMAGE_NT_HEADERS32*)malloc(sizeof(IMAGE_NT_HEADERS32));
        if (((t_pe32*)pe)->pe_header == NULL) {
            deallocate_pe_pe_header(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe32*)pe)->pe_header, file_data + ((t_pe32*)pe)->dos_header->e_lfanew, sizeof(IMAGE_NT_HEADERS32));

        if ((((t_pe32*)pe)->pe_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) { // NOLINT(hicpp-signed-bitwise)
            deallocate_pe_pe_header(pe);
            log_error("The file is not an executable");
            return -1;
        }

        if (((t_pe32*)pe)->pe_header->FileHeader.SizeOfOptionalHeader == 0) {
            deallocate_pe_pe_header(pe);
            log_error("The file is an OBJ file");
            return -1;
        }
        //recheck, just4sure
        if (((t_pe32*)pe)->pe_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            deallocate_pe_pe_header(pe);
            log_error("File is not an executable image");
            return -1;
        }

        log_verbose("Entry point address: 0x%x", ((t_pe32*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);
    }
    else {
        if (file_data_size < sizeof(IMAGE_NT_HEADERS64)) {
            log_error("Total file size is less than PE Header size");
            return -1;
        }

        ((t_pe64*)pe)->pe_header = (IMAGE_NT_HEADERS64*)malloc(sizeof(IMAGE_NT_HEADERS64));
        if (((t_pe64*)pe)->pe_header == NULL) {
            deallocate_pe_pe_header(pe);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(((t_pe64*)pe)->pe_header, file_data + ((t_pe64*)pe)->dos_header->e_lfanew, sizeof(IMAGE_NT_HEADERS64));

        if ((((t_pe64*)pe)->pe_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) { // NOLINT(hicpp-signed-bitwise)
            deallocate_pe_pe_header(pe);
            log_error("The file is not an executable");
            return -1;
        }

        if (((t_pe64*)pe)->pe_header->FileHeader.SizeOfOptionalHeader == 0) {
            deallocate_pe_pe_header(pe);
            log_error("The file is an OBJ file");
            return -1;
        }
        //recheck, just4sure
        if (((t_pe64*)pe)->pe_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            deallocate_pe_pe_header(pe);
            log_error("File is not an executable image");
            return -1;
        }
        log_verbose("Entry point address: 0x%x", ((t_pe64*)pe)->pe_header->OptionalHeader.AddressOfEntryPoint);
    }

    return 1;
}

int allocate_pe_sections_headers(t_pe* pe, void* file_data, size_t file_data_size) {
    if (pe->s_type == PE32) {
        size_t pe_sections_header_size = sizeof(IMAGE_SECTION_HEADER) * ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections;

        ((t_pe32*)pe)->section_header = (IMAGE_SECTION_HEADER*)malloc(pe_sections_header_size);
        if (((t_pe32*)pe)->section_header == NULL) {
            deallocate_pe_sections_headers(pe);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_pe32*)pe)->section_header, 0, pe_sections_header_size);

        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (file_data_size <
                ((t_pe32*)pe)->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (i * sizeof(IMAGE_SECTION_HEADER))) {
                deallocate_pe_sections_headers(pe);
                log_error("Total file size is inferior to PE section header size");
                return -1;
            }
            memcpy(&(((t_pe32*)pe)->section_header[i]), file_data + ((t_pe32*)pe)->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) +
                (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
        }
    }
    else {
        size_t pe_sections_header_size = sizeof(IMAGE_SECTION_HEADER) * ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;

        ((t_pe64*)pe)->section_header = (IMAGE_SECTION_HEADER*)malloc(pe_sections_header_size);
        if (((t_pe64*)pe)->section_header == NULL) {
            deallocate_pe_sections_headers(pe);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_pe64*)pe)->section_header, 0, pe_sections_header_size);

        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (file_data_size <
                ((t_pe64*)pe)->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + (i * sizeof(IMAGE_SECTION_HEADER))) {
                deallocate_pe_sections_headers(pe);
                log_error("Total file size is inferior to PE section header size");
                return -1;
            }
            memcpy(&(((t_pe64*)pe)->section_header[i]), file_data + ((t_pe64*)pe)->dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) +
                (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
        }
    }

    return 1;
}

int allocate_pe_sections_data(t_pe* pe, void* file_data, size_t file_data_size) {
    if (pe->s_type == PE32) {
        size_t section_data_size = sizeof(char*) * ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections;

        ((t_pe32*)pe)->section_data = (char**)malloc(section_data_size);
        if (((t_pe32*)pe)->section_data == NULL) {
            deallocate_pe_sections_data(pe);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_pe32*)pe)->section_data, 0, section_data_size);
        size_t pe_section_data_size{};
        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (((t_pe32*)pe)->section_header[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                ((t_pe32*)pe)->section_data[i] = NULL;
            }
            else {
                if (file_data_size < ((t_pe32*)pe)->section_header[i].PointerToRawData) {
                    log_error("Total file size is less than section data offset");
                    return -1;
                }
                pe_section_data_size = ((t_pe32*)pe)->section_header[i].SizeOfRawData;
                ((t_pe32*)pe)->section_data[i] = (char*)malloc(pe_section_data_size);
                if (((t_pe32*)pe)->section_data[i] == NULL) {
                    free(((t_pe32*)pe)->section_data[i]);
                    log_error("malloc() error");
                    return -1;
                }
                memset(((t_pe32*)pe)->section_data[i], 0, pe_section_data_size);
                memcpy(((t_pe32*)pe)->section_data[i], file_data + ((t_pe32*)pe)->section_header[i].PointerToRawData, pe_section_data_size);
            }
        }
    }
    else {
        size_t section_data_size = sizeof(char*) * ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;

        ((t_pe64*)pe)->section_data = (char**)malloc(section_data_size);
        if (((t_pe64*)pe)->section_data == NULL) {
            deallocate_pe_sections_data(pe);
            log_error("malloc() failure");
            return -1;
        }
        memset(((t_pe64*)pe)->section_data, 0, section_data_size);
        size_t pe_section_data_size{};
        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            if (((t_pe64*)pe)->section_header[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
                ((t_pe64*)pe)->section_data[i] = NULL;
            }
            else {
                if (file_data_size < ((t_pe64*)pe)->section_header[i].PointerToRawData) {
                    log_error("Total file size is less than section data offset");
                    return -1;
                }
                pe_section_data_size = ((t_pe64*)pe)->section_header[i].SizeOfRawData;
                ((t_pe64*)pe)->section_data[i] = (char*)malloc(pe_section_data_size);
                if (((t_pe64*)pe)->section_data[i] == NULL) {
                    free(((t_pe64*)pe)->section_data[i]);
                    log_error("malloc() error");
                    return -1;
                }
                memset(((t_pe64*)pe)->section_data[i], 0, pe_section_data_size);
                memcpy(((t_pe64*)pe)->section_data[i], file_data + ((t_pe64*)pe)->section_header[i].PointerToRawData, pe_section_data_size);
            }
        }
    }
    return 1;
}

int allocate_pe_overlay(t_pe* pe, void* file_data, size_t file_data_size) {
    if (pe->s_type == PE32) {
        uint16_t sections_count = ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections;
        size_t end_of_pe = ((t_pe32*)pe)->section_header[sections_count - 1].PointerToRawData + ((t_pe32*)pe)->section_header[sections_count - 1].SizeOfRawData;
        if (file_data_size > end_of_pe) {
            size_t overlay_size = file_data_size - end_of_pe;
            log_verbose("Allocating Overlay Data ...");
            ((t_pe32*)pe)->overlay = (char*)malloc(overlay_size);
            if (((t_pe32*)pe)->overlay == NULL) {
                log_error("malloc() error");
                return -1;
            }
            memcpy(((t_pe32*)pe)->overlay, (char*)file_data + end_of_pe, overlay_size);
            ((t_pe32*)pe)->overlay_size = overlay_size;
        }
    }
    else {
        uint16_t sections_count = ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;
        size_t end_of_pe = ((t_pe64*)pe)->section_header[sections_count - 1].PointerToRawData + ((t_pe64*)pe)->section_header[sections_count - 1].SizeOfRawData;
        if (file_data_size > end_of_pe) {
            size_t overlay_size = file_data_size - end_of_pe;
            log_verbose("Allocating Overlay Data ...");
            ((t_pe64*)pe)->overlay = (char*)malloc(overlay_size);
            if (((t_pe64*)pe)->overlay == NULL) {
                log_error("malloc() error");
                return -1;
            }
            memcpy(((t_pe64*)pe)->overlay, (char*)file_data + end_of_pe, overlay_size);
            ((t_pe64*)pe)->overlay_size = overlay_size;
        }
    }
    return 1;
}

int allocate_pe(t_pe** pe, void* file_data, size_t file_data_size, int arch) {
    size_t t_pe_size{};
    if (packer_config.bit == x32_ARCH) {
        t_pe_size = sizeof(t_pe32);
    }
    else {
        t_pe_size = sizeof(t_pe64);
    }

    *pe = (t_pe*)malloc(t_pe_size);
    if (*pe == NULL) {
        deallocate_pe_struct(*pe);
        log_error("malloc() failure");
        return -1;
    }
    memset(*pe, 0, t_pe_size);

    t_pe type_pe{};
    if (packer_config.bit == x32_ARCH) {
        type_pe.s_type = PE32;
        ((t_pe32*)(*pe))->type_header = type_pe;
    }
    else {
        type_pe.s_type = PE64;
        ((t_pe32*)(*pe))->type_header = type_pe;
    }

    log_verbose("Allocating DOS Header ...");
    if (allocate_pe_dos_header(*pe, file_data, file_data_size) == -1) {
        deallocate_pe_struct(*pe);
        log_error("Error during DOS Header allocation");
        return -1;
    }

    log_verbose("Allocating DOS Stub ...");
    if (allocate_pe_dos_stub(*pe, file_data) == -1) {
        deallocate_pe_dos_header(*pe);
        deallocate_pe_struct(*pe);
        log_error("Error during DOS Stub allocation");
        return -1;
    }

    log_verbose("Allocating PE Header ...");
    if (allocate_pe_pe_header(*pe, file_data, file_data_size) == -1) {
        deallocate_pe_dos_header(*pe);
        deallocate_pe_dos_stub(*pe);
        deallocate_pe_struct(*pe);
        log_error("Error during PE Header allocation");
        return -1;
    }

    log_verbose("Allocating Sections Headers ...");
    if (allocate_pe_sections_headers(*pe, file_data, file_data_size) == -1) {
        deallocate_pe_dos_header(*pe);
        deallocate_pe_dos_stub(*pe);
        deallocate_pe_pe_header(*pe);
        deallocate_pe_struct(*pe);
        log_error("Error during Section Headers allocation");
        return -1;
    }

    log_verbose("Allocating Sections Data ...");
    if (allocate_pe_sections_data(*pe, file_data, file_data_size) == -1) {
        deallocate_pe_dos_header(*pe);
        deallocate_pe_dos_stub(*pe);
        deallocate_pe_pe_header(*pe);
        deallocate_pe_sections_headers(*pe);
        deallocate_pe_struct(*pe);
        log_error("Error during Section Data allocation");
        return -1;
    }

    if (allocate_pe_overlay(*pe, file_data, file_data_size) == -1) {
        deallocate_pe_dos_header(*pe);
        deallocate_pe_dos_stub(*pe);
        deallocate_pe_pe_header(*pe);
        deallocate_pe_sections_headers(*pe);
        deallocate_pe_struct(*pe);
        log_error("Error during Overlay allocation");
        return -1;
    }

    return 1;
}