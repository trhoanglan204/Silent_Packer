#include "pe_section_insertion.h"
#include "pe_struct.h"
#include "pe_allocation.h"
#include "pe_functions.h"
#include "loader_functions.h"
#include "file_functions.h"
#include "packer_config.h"
#include "all_pe_loaders_infos.h"
#include "helper.h"

#include <time.h>
#include <vector>
#include <string>

#define ROUND_UP(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))

static std::vector<std::string> all_sections{};

static void get_all_section_name(t_pe* pe) {
    all_sections.clear();
    char section_name[9] = { 0 };
    if (pe->s_type == PE32) {
        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            memcpy(section_name, ((t_pe32*)pe)->section_header[i].Name, 8);
            all_sections.push_back(std::string(section_name));
        }
    }
    else {
        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            memcpy(section_name, ((t_pe64*)pe)->section_header[i].Name, 8);
            all_sections.push_back(std::string(section_name));
        }
    }
}

static bool section_name_exists(const std::string& name) {
    for (const auto& existing_name : all_sections) {
        if (existing_name == name) {
            return true;
        }
    }
    return false;
}

static char* generate_random_section_name() {
    srand(time(NULL));
    int len = rand() % 3 + 4; //len : 4, 5, 6
    static char new_section_name[9] = { 0 };
    while (true) {
        new_section_name[0] = '.';
        for (int i = 1; i < len + 1; i++) {
            new_section_name[i] = 'a' + (rand() % 26);
        }
        new_section_name[len + 1] = '\0';
        std::string generated_name(new_section_name);
        if (!section_name_exists(generated_name)) {
            break;
        }
    }

    return new_section_name;
}

int add_new_pe_section_header(t_pe* pe) {
    get_all_section_name(pe);

    int sections_count = (pe->s_type == PE32) ? ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections
        : ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;

    size_t new_section_header_size = sections_count * sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_SECTION_HEADER);

    IMAGE_SECTION_HEADER* new_section_header{};

    if (pe->s_type == PE32) {
        new_section_header = (IMAGE_SECTION_HEADER*)realloc(((t_pe32*)pe)->section_header, new_section_header_size);
        if (new_section_header == NULL) {
            log_error("realloc() failure\n");
            return -1;
        }
        ((t_pe32*)pe)->section_header = new_section_header;
    }
    else {
        new_section_header = (IMAGE_SECTION_HEADER*)realloc(((t_pe64*)pe)->section_header, new_section_header_size);
        if (new_section_header == NULL) {
            log_error("realloc() failure\n");
            return -1;
        }
        ((t_pe64*)pe)->section_header = new_section_header;
    }

    IMAGE_SECTION_HEADER new_header{ 0 };

    char* section_name = generate_random_section_name();
    memcpy(new_header.Name, section_name, IMAGE_SIZEOF_SHORT_NAME); //ensure
    log_info("New section name: %s", new_header.Name);

    if (pe->s_type == PE32) {
        new_header.VirtualAddress = ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfImage;
        new_header.PointerToRawData = ((t_pe32*)pe)->section_header[sections_count - 1].PointerToRawData +
            ((t_pe32*)pe)->section_header[sections_count - 1].SizeOfRawData;

        new_header.Misc.VirtualSize = packer_config.loader_size;

        // TO SEE
        uint32_t FileAlignment = ((t_pe32*)pe)->pe_header->OptionalHeader.FileAlignment;

        new_header.SizeOfRawData = ROUND_UP(packer_config.loader_size, FileAlignment);

        new_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE; // NOLINT(hicpp-signed-bitwise)

        memcpy(&(((t_pe32*)pe)->section_header[sections_count]), &new_header, sizeof(IMAGE_SECTION_HEADER));
    }
    else {
        new_header.VirtualAddress = ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfImage;
        new_header.PointerToRawData = ((t_pe64*)pe)->section_header[sections_count - 1].PointerToRawData +
            ((t_pe64*)pe)->section_header[sections_count - 1].SizeOfRawData;

        new_header.Misc.VirtualSize = packer_config.loader_size;

        // TO SEE
        uint32_t FileAlignment = ((t_pe64*)pe)->pe_header->OptionalHeader.FileAlignment;

        new_header.SizeOfRawData = ROUND_UP(packer_config.loader_size, FileAlignment);

        new_header.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE; // NOLINT(hicpp-signed-bitwise)

        memcpy(&(((t_pe64*)pe)->section_header[sections_count]), &new_header, sizeof(IMAGE_SECTION_HEADER));
    }

    return 1;
}

int set_new_pe_header_values(t_pe* pe) {
    if (pe->s_type == PE32) {
        uint16_t old_sections_count = ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections;

        uint32_t SectionAlignment = ((t_pe32*)pe)->pe_header->OptionalHeader.SectionAlignment;
        uint32_t FileAlignment = ((t_pe32*)pe)->pe_header->OptionalHeader.FileAlignment;
        uint32_t SizeOfImage = ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfImage;
        SizeOfImage += packer_config.loader_size;
        uint32_t SizeOfHeaders = ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfHeaders;
        uint32_t newSizeOfHeaders = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER32) + sizeof(IMAGE_SECTION_HEADER) * old_sections_count;
        newSizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);

        ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections += 1;

        ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfCode += ((t_pe32*)pe)->section_header[old_sections_count - 1].SizeOfRawData;
        if (SizeOfHeaders < newSizeOfHeaders) {
            ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfHeaders = ROUND_UP(newSizeOfHeaders, FileAlignment);
        }
        ((t_pe32*)pe)->pe_header->OptionalHeader.SizeOfImage = ROUND_UP(SizeOfImage, SectionAlignment);
    }
    else {
        uint16_t old_sections_count = ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;

        uint32_t SectionAlignment = ((t_pe64*)pe)->pe_header->OptionalHeader.SectionAlignment;
        uint32_t FileAlignment = ((t_pe64*)pe)->pe_header->OptionalHeader.FileAlignment;
        uint32_t SizeOfImage = ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfImage;
        SizeOfImage += packer_config.loader_size;
        uint32_t SizeOfHeaders = ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfHeaders;
        uint32_t newSizeOfHeaders = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) + sizeof(IMAGE_SECTION_HEADER) * old_sections_count;
        newSizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);

        ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections += 1;

        ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfCode += ((t_pe64*)pe)->section_header[old_sections_count - 1].SizeOfRawData;
        if (SizeOfHeaders < newSizeOfHeaders) {
            ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfHeaders = ROUND_UP(newSizeOfHeaders, FileAlignment);
        }
        ((t_pe64*)pe)->pe_header->OptionalHeader.SizeOfImage = ROUND_UP(SizeOfImage, SectionAlignment);
    }

    return 1;
}

int add_new_pe_section_data(t_pe* pe) {
    char* loader{};

    if (pe->s_type == PE32) {
        int sections_count = ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections;
        char** new_section_data = (char**)realloc(((t_pe32*)pe)->section_data, sizeof(char*) * sections_count);
        if (new_section_data == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        ((t_pe32*)pe)->section_data = new_section_data;

        // For ASM
        loader_offset32 = ((t_pe32*)pe)->section_header[sections_count - 1].VirtualAddress;

        loader = patch_loader();
        if (loader == NULL) {
            free(loader);
            log_error("Error during loader patching");
            return -1;
        }
        char* new_section = (char*)malloc(((t_pe32*)pe)->section_header[sections_count - 1].SizeOfRawData);
        if (new_section == NULL) {
            free(loader);
            free(new_section);
            log_error("malloc() failure");
            return -1;
        }
        memset(new_section, 0, ((t_pe32*)pe)->section_header[sections_count - 1].SizeOfRawData);
        memcpy(new_section, loader, packer_config.loader_size);
        ((t_pe32*)pe)->section_data[sections_count - 1] = new_section;
    }
    else {
        int sections_count = ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections;
        char** new_section_data = (char**)realloc(((t_pe64*)pe)->section_data, sizeof(char*) * sections_count);
        if (new_section_data == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        ((t_pe64*)pe)->section_data = new_section_data;

        // For ASM
        loader_offset64 = ((t_pe64*)pe)->section_header[sections_count - 1].VirtualAddress;

        loader = patch_loader();
        if (loader == NULL) {
            free(loader);
            log_error("Error during loader patching");
            return -1;
        }
        char* new_section = (char*)malloc(((t_pe64*)pe)->section_header[sections_count - 1].SizeOfRawData);
        if (new_section == NULL) {
            free(loader);
            free(new_section);
            log_error("malloc() failure");
            return -1;
        }
        memset(new_section, 0, ((t_pe64*)pe)->section_header[sections_count - 1].SizeOfRawData);
        memcpy(new_section, loader, packer_config.loader_size);
        ((t_pe64*)pe)->section_data[sections_count - 1] = new_section;
    }
    free(loader);

    return 1;
}

int pe_insert_section(t_pe* pe) {
    int text_section_index = find_pe_text_section(pe);
    if (text_section_index == -1) {
        log_error("Couldn't find .text section");
        return -1;
    }
    add_pe_section_permission(pe, text_section_index, IMAGE_SCN_MEM_WRITE);

    log_verbose("Creating new section ...");

    if (add_new_pe_section_header(pe) == -1) {
        log_error("Error during new Section Header insertion");
        return -1;
    }

    log_verbose("Setting new sections headers values ...");

    if (set_new_pe_header_values(pe) == -1) {
        log_error("Couldn't set new PE Header values");
        return -1;
    }

    log_verbose("Inserting the section data ...");

    if (add_new_pe_section_data(pe) == -1) {
        log_error("Error during new Section Data insertion");
        return -1;
    }

    int idx{};
    if (pe->s_type == PE32) {
        idx = ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections - 1;
    }
    else {
        idx = ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections - 1;
    }

    log_verbose("Relocate RVA DataDirectory ...");
    relocate_pe_RVA(pe, idx);

    log_verbose("Setting new PE entry point ...");
    set_new_pe_entry_to_section(pe, idx);

    log_verbose("Recalculate Checksum ...");
    recalculate_pe_checksum(pe);

    return 1;
}