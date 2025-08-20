#include "elf_section_insertion.h"
#include "elf_packing_method.h"
#include "elf_functions.h"
#include "loader_functions.h"
#include "packer_config.h"
#include "file_functions.h"
#include "all_elf_loaders_infos.h"
#include "helper.h"

#include <time.h>
#include <string>
#include <vector>

Elf64_Shdr new_section64 = {
        .sh_name = 0,
        .sh_type = take_byte32(SHT_PROGBITS,packer_config.endianess),
        .sh_flags = take_byte64(SHF_EXECINSTR | SHF_ALLOC,packer_config.endianess), // NOLINT(hicpp-signed-bitwise)
        .sh_addr = 0,
        .sh_offset = 0,
        .sh_size = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = take_byte64(16,packer_config.endianess),
        .sh_entsize = 0,
};

Elf32_Shdr new_section32 = {
        .sh_name = 0,
        .sh_type = take_byte32(SHT_PROGBITS,packer_config.endianess),
        .sh_flags = take_byte32(SHF_EXECINSTR | SHF_ALLOC,packer_config.endianess), // NOLINT(hicpp-signed-bitwise)
        .sh_addr = 0,
        .sh_offset = 0,
        .sh_size = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = take_byte32(16,packer_config.endianess),
        .sh_entsize = 0,
};

static std::vector<std::string> all_sections{};

static void get_all_section_name(t_elf* elf) {
    all_sections.clear();
    char section_name[256] = { 0 };
    if (elf->s_type == ELF32) {
        int section_string_table_index = take_byte16(((t_elf32*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            const char* name = ((char*)(((t_elf32*)elf)->section_data[section_string_table_index] + take_byte32(((t_elf32*)elf)->section_header[i].sh_name, packer_config.endianess)));
            all_sections.push_back(std::string(name));
        }
    }
    else {
        int section_string_table_index = take_byte16(((t_elf64*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            char* name = ((char*)(((t_elf64*)elf)->section_data[section_string_table_index] + take_byte32(((t_elf64*)elf)->section_header[i].sh_name, packer_config.endianess)));
            all_sections.push_back(std::string(name));
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
    int len = rand() % 6 + 5;
    static char new_section_name[12];

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

int set_new_elf_section_string_table(t_elf* elf) {
    char* new_string_table{};
    get_all_section_name(elf);
    char* section_name = generate_random_section_name();
    log_info("New section name: %s", section_name);
    size_t section_name_length = strlen(section_name);
    if (elf->s_type == ELF32) {
        int section_string_table_index = take_byte16(((t_elf32*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        size_t old_size = take_byte32(((t_elf32*)elf)->section_header[section_string_table_index].sh_size, packer_config.endianess);
        size_t new_string_table_size = old_size + section_name_length + 1;
        new_string_table = (char*)realloc(((t_elf32*)elf)->section_data[section_string_table_index], new_string_table_size);
        if (new_string_table == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        memcpy(new_string_table + old_size, section_name, section_name_length + 1);
        // We set it to the end of the old section_string_table
        new_section32.sh_name = take_byte32(old_size, packer_config.endianess);
        ((t_elf32*)elf)->section_data[section_string_table_index] = new_string_table;
        ((t_elf32*)elf)->section_header[section_string_table_index].sh_size = take_byte32(new_string_table_size, packer_config.endianess);
    }
    else {
        int section_string_table_index = take_byte16(((t_elf64*)elf)->elf_header->e_shstrndx, packer_config.endianess);
        size_t old_size = take_byte64(((t_elf64*)elf)->section_header[section_string_table_index].sh_size, packer_config.endianess);
        size_t new_string_table_size = old_size + section_name_length + 1;
        new_string_table = (char*)realloc(((t_elf64*)elf)->section_data[section_string_table_index], new_string_table_size);
        if (new_string_table == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        memcpy(new_string_table + old_size, section_name, section_name_length + 1);
        // We set it to the end of the old section_string_table
        new_section64.sh_name = take_byte32(old_size, packer_config.endianess);
        ((t_elf64*)elf)->section_data[section_string_table_index] = new_string_table;
        ((t_elf64*)elf)->section_header[section_string_table_index].sh_size = take_byte64(new_string_table_size, packer_config.endianess);
    }

    return 1;
}

int set_new_elf_section_symtab_sh_link_value(t_elf* elf) {
    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            char* section_name = find_elf_section_name(elf, i);
            if (strcmp(section_name, ".symtab") == 0) {
                uint32_t sh_link = take_byte32(((t_elf32*)elf)->section_header[i].sh_link, packer_config.endianess);
                sh_link += 1;
                ((t_elf32*)elf)->section_header[i].sh_link = take_byte32(sh_link, packer_config.endianess);
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess); i++) {
            char* section_name = find_elf_section_name(elf, i);
            if (strcmp(section_name, ".symtab") == 0) {
                uint32_t sh_link = take_byte32(((t_elf64*)elf)->section_header[i].sh_link, packer_config.endianess);
                sh_link += 1;
                ((t_elf64*)elf)->section_header[i].sh_link = take_byte32(sh_link, packer_config.endianess);
            }
        }
    }

    return 1;
}

/* Map example
     *
     * --------
     * loadable1
     * --------
     * loadable2
     * --------
     * loadable3 --> last_loadable_section_index
     * --------
     * non_loadable1
     * --------
     * non_loadable2
     * --------
     * new_created_empty_section
     * --------
     *
     * We change it to this :
     *
     * --------
     * loadable1
     * --------
     * loadable2
     * --------
     * loadable3 --> last_loadable_section_index
     * --------
     * new_section_loadable4
     * --------
     * non_loadable1
     * --------
     * non_loadable2
     * --------
     *
*/

int elf_section_create_new_section(t_elf* elf, int last_pt_load_index, int last_loadable_section_index) {
    char** new_section_data{};
    char* loader{};
    if (elf->s_type == ELF32) {
        Elf32_Shdr* new_section_headers{};
        uint16_t e_shnum_host = take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess);
        e_shnum_host += 1;
        ((t_elf32*)elf)->elf_header->e_shnum = take_byte16(e_shnum_host, packer_config.endianess);
        size_t new_section_headers_size = sizeof(Elf32_Shdr) * e_shnum_host;
        new_section_headers = (Elf32_Shdr*)realloc(((t_elf32*)elf)->section_header, new_section_headers_size);
        if (new_section_headers == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        size_t new_section_data_size = sizeof(char*) * e_shnum_host;
        new_section_data = (char**)realloc(((t_elf32*)elf)->section_data, new_section_data_size);
        if (new_section_data == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        ((t_elf32*)elf)->section_header = new_section_headers;
        ((t_elf32*)elf)->section_data = new_section_data;
        new_section32.sh_offset = take_byte32(
            take_byte32(((t_elf32*)elf)->prog_header[last_pt_load_index].p_offset, packer_config.endianess) + take_byte32(((t_elf32*)elf)->prog_header[last_pt_load_index].p_memsz, packer_config.endianess), packer_config.endianess);
        new_section32.sh_addr = take_byte32(
            take_byte32(((t_elf32*)elf)->prog_header[last_pt_load_index].p_vaddr, packer_config.endianess) + take_byte32(((t_elf32*)elf)->prog_header[last_pt_load_index].p_memsz, packer_config.endianess), packer_config.endianess);
        new_section32.sh_size = take_byte32(packer_config.loader_size, packer_config.endianess);

        // For ASM
        loader_offset32 = new_section32.sh_addr;
        loader = patch_loader();
        if (loader == NULL) {
            free(loader);
            log_error("Error during loader patching");
            return -1;
        }
        // -1 because e_shnum starts at 1 / -1 because we created an empty section which doesn't count
        size_t remaining_after_section_headers_data_size =
            sizeof(Elf32_Shdr) * (take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess) - last_loadable_section_index - 1 - 1);
        size_t remaining_after_section_headers_count =
            sizeof(char*) * (take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess) - last_loadable_section_index - 1 - 1);
        // We move all sections after the last loadable section to + 1
        memmove(new_section_headers + last_loadable_section_index + 2,
            new_section_headers + last_loadable_section_index + 1, remaining_after_section_headers_data_size);
        // Shift all char * pointer after the last loadable section to + 1
        memmove(new_section_data + last_loadable_section_index + 2, new_section_data + last_loadable_section_index + 1,
            remaining_after_section_headers_count);

        last_loadable_section_index += 1;
        // Shift all char * pointer after the last loadable section to + 1
        // Shift all char * pointer after the last loadable section to + 1
        if (take_byte16(((t_elf32*)elf)->elf_header->e_shstrndx, packer_config.endianess) >= last_loadable_section_index) {
            uint16_t e_shstrndx = take_byte16(((t_elf32*)elf)->elf_header->e_shstrndx, packer_config.endianess);
            e_shstrndx += 1;
            ((t_elf32*)elf)->elf_header->e_shstrndx = take_byte16(e_shstrndx, packer_config.endianess);
        }
        if (set_new_elf_section_string_table(elf) == -1) {
            free(loader);
            log_error("Error setting new string table");
            return -1;
        }
        memcpy(new_section_headers + last_loadable_section_index, &new_section32, sizeof(Elf32_Shdr));
        char* new_section_d = (char*)malloc(take_byte32(new_section32.sh_size, packer_config.endianess));
        if (new_section_d == NULL) {
            free(loader);
            free(new_section_d);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(new_section_d, loader, packer_config.loader_size);
        ((t_elf32*)elf)->section_data[last_loadable_section_index] = new_section_d;
    }
    else {
        Elf64_Shdr* new_section_headers{};
        uint16_t e_shnum_host = take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess);
        e_shnum_host += 1;
        ((t_elf64*)elf)->elf_header->e_shnum = take_byte16(e_shnum_host, packer_config.endianess);
        size_t new_section_headers_size = sizeof(Elf64_Shdr) * e_shnum_host;
        new_section_headers = (Elf64_Shdr*)realloc(((t_elf64*)elf)->section_header, new_section_headers_size);
        if (new_section_headers == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        size_t new_section_data_size = sizeof(char*) * e_shnum_host;
        new_section_data = (char**)realloc(((t_elf64*)elf)->section_data, new_section_data_size);
        if (new_section_data == NULL) {
            log_error("realloc() failure");
            return -1;
        }
        ((t_elf64*)elf)->section_header = new_section_headers;
        ((t_elf64*)elf)->section_data = new_section_data;
        new_section64.sh_offset = take_byte64(
            take_byte64(((t_elf64*)elf)->prog_header[last_pt_load_index].p_offset, packer_config.endianess) + take_byte64(((t_elf64*)elf)->prog_header[last_pt_load_index].p_memsz, packer_config.endianess), packer_config.endianess);
        new_section64.sh_addr = take_byte64(
            take_byte64(((t_elf64*)elf)->prog_header[last_pt_load_index].p_vaddr, packer_config.endianess) + take_byte64(((t_elf64*)elf)->prog_header[last_pt_load_index].p_memsz, packer_config.endianess), packer_config.endianess);
        new_section64.sh_size = take_byte64(packer_config.loader_size, packer_config.endianess);

        // For ASM
        loader_offset64 = new_section64.sh_addr;
        loader = patch_loader();
        if (loader == NULL) {
            free(loader);
            log_error("Error during loader patching");
            return -1;
        }
        // -1 because e_shnum starts at 1 / -1 because we created an empty section which doesn't count
        size_t remaining_after_section_headers_data_size =
            sizeof(Elf64_Shdr) * (take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess) - last_loadable_section_index - 1 - 1);
        size_t remaining_after_section_headers_count =
            sizeof(char*) * (take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess) - last_loadable_section_index - 1 - 1);
        // We move all sections after the last loadable section to + 1
        memmove(new_section_headers + last_loadable_section_index + 2,
            new_section_headers + last_loadable_section_index + 1, remaining_after_section_headers_data_size);
        // Shift all char * pointer after the last loadable section to + 1
        memmove(new_section_data + last_loadable_section_index + 2, new_section_data + last_loadable_section_index + 1,
            remaining_after_section_headers_count);

        last_loadable_section_index += 1;
        // Shift all char * pointer after the last loadable section to + 1
        // Shift all char * pointer after the last loadable section to + 1
        if (take_byte16(((t_elf64*)elf)->elf_header->e_shstrndx, packer_config.endianess) >= last_loadable_section_index) {
            uint16_t e_shstrndx = take_byte16(((t_elf64*)elf)->elf_header->e_shstrndx, packer_config.endianess);
            e_shstrndx += 1;
            ((t_elf64*)elf)->elf_header->e_shstrndx = take_byte16(e_shstrndx, packer_config.endianess);
        }
        if (set_new_elf_section_string_table(elf) == -1) {
            free(loader);
            log_error("Error setting new string table");
            return -1;
        }
        memcpy(new_section_headers + last_loadable_section_index, &new_section64, sizeof(Elf64_Shdr));
        char* new_section_d = (char*)malloc(take_byte64(new_section64.sh_size, packer_config.endianess));
        if (new_section_d == NULL) {
            free(loader);
            free(new_section_d);
            log_error("malloc() failure");
            return -1;
        }
        memcpy(new_section_d, loader, packer_config.loader_size);
        ((t_elf64*)elf)->section_data[last_loadable_section_index] = new_section_d;
    }
    free(loader);
    if (set_new_elf_section_symtab_sh_link_value(elf) == -1) {
        log_error("Error modifying symtab sh_link value");
        return -1;
    }
    return 1;
}

static int elf_section_set_new_segment_values(t_elf* elf, int segment_index) {
    if (elf->s_type == ELF32) {
        size_t new_segment_size = take_byte32(((t_elf32*)elf)->prog_header[segment_index].p_memsz, packer_config.endianess) + packer_config.loader_size;
        ((t_elf32*)elf)->prog_header[segment_index].p_memsz = take_byte32(new_segment_size, packer_config.endianess);
        ((t_elf32*)elf)->prog_header[segment_index].p_filesz = take_byte32(new_segment_size, packer_config.endianess);
    }
    else {
        size_t new_segment_size = take_byte64(((t_elf64*)elf)->prog_header[segment_index].p_memsz, packer_config.endianess) + packer_config.loader_size;
        ((t_elf64*)elf)->prog_header[segment_index].p_memsz = take_byte64(new_segment_size, packer_config.endianess);
        ((t_elf64*)elf)->prog_header[segment_index].p_filesz = take_byte64(new_segment_size, packer_config.endianess);
    }

    set_new_elf_section_pt_loader_permissions(elf);

    return 1;
}

static int elf_section_set_new_section_values(t_elf* elf, int section_index) {
    if (elf->s_type == ELF32) {
        for (int i = section_index; i < take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess) - 1; i++) {
            ((t_elf32*)elf)->section_header[i + 1].sh_offset = take_byte32(take_byte32(((t_elf32*)elf)->section_header[i].sh_offset, packer_config.endianess) + take_byte32(((t_elf32*)elf)->section_header[i].sh_size, packer_config.endianess), packer_config.endianess);
        }
        int section_count = take_byte16(((t_elf32*)elf)->elf_header->e_shnum, packer_config.endianess);
        ((t_elf32*)elf)->elf_header->e_shoff = take_byte32(take_byte32(((t_elf32*)elf)->section_header[section_count - 1].sh_offset, packer_config.endianess) + take_byte32(((t_elf32*)elf)->section_header[section_count - 1].sh_size, packer_config.endianess), packer_config.endianess);
    }
    else {
        for (int i = section_index; i < take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess) - 1; i++) {
            ((t_elf64*)elf)->section_header[i + 1].sh_offset = take_byte64(take_byte64(((t_elf64*)elf)->section_header[i].sh_offset, packer_config.endianess) + take_byte64(((t_elf64*)elf)->section_header[i].sh_size, packer_config.endianess), packer_config.endianess);
        }
        int section_count = take_byte16(((t_elf64*)elf)->elf_header->e_shnum, packer_config.endianess);
        ((t_elf64*)elf)->elf_header->e_shoff = take_byte64(take_byte64(((t_elf64*)elf)->section_header[section_count - 1].sh_offset, packer_config.endianess) + take_byte64(((t_elf64*)elf)->section_header[section_count - 1].sh_size, packer_config.endianess), packer_config.endianess);
    }
    return 1;
}

int set_new_elf_section_pt_loader_permissions(t_elf* elf) {
    uint32_t pt_loader = take_byte32(PT_LOAD, packer_config.endianess);
    uint32_t pf = take_byte32(PF_X | PF_W | PF_R, packer_config.endianess);
    if (elf->s_type == ELF32) {
        for (int i = 0; i < take_byte16(((t_elf32*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (((t_elf32*)elf)->prog_header[i].p_type == pt_loader) {
                ((t_elf32*)elf)->prog_header[i].p_flags = pf; // NOLINT(hicpp-signed-bitwise)
            }
        }
    }
    else {
        for (int i = 0; i < take_byte16(((t_elf64*)elf)->elf_header->e_phnum, packer_config.endianess); i++) {
            if (((t_elf64*)elf)->prog_header[i].p_type == pt_loader) {
                ((t_elf64*)elf)->prog_header[i].p_flags = pf; // NOLINT(hicpp-signed-bitwise)
            }
        }
    }
    return 1;
}

int elf_insert_section(t_elf* elf) {
    int last_pt_load_index = find_last_elf_segment_of_type(elf, take_byte32(PT_LOAD, packer_config.endianess));
    if (last_pt_load_index == -1) {
        log_error("Couldn't find PT_LOAD segment");
        return -1;
    }
    int last_loadable_section_index = find_last_elf_section_from_segment(elf, last_pt_load_index);
    if (last_loadable_section_index == -1) {
        log_error("Couldn't find the last Section index");
        return -1;
    }
    log_verbose("Creating new section ...");
    if (elf_section_create_new_section(elf, last_pt_load_index, last_loadable_section_index) == -1) {
        log_error("Error during new Section creation");
        return -1;
    }
    last_loadable_section_index += 1;

    log_verbose("Setting new segment values ...");

    if (elf_section_set_new_segment_values(elf, last_pt_load_index) == -1) {
        log_error("Couldn't set new segment values");
        return -1;
    }

    log_verbose("Setting new section values ...");

    if (elf_section_set_new_section_values(elf, last_loadable_section_index) == -1) {
        log_error("Couldn't set new section values");
        return -1;
    }

    log_verbose("Setting new ELF entry point ...");

    set_new_elf_entry_to_section(elf, last_loadable_section_index);
    return 1;
}