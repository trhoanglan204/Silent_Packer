#include "elf_packing_method.h"
#include "elf_allocation.h"
#include "packer_config.h"
#include "elf_packing.h"
#include "elf_section_insertion.h"
#include "elf_code_cave.h"
#include <helper.h>

int elf_pack_using_method(t_elf* elf) {
    if (strcmp(packer_config.packing_method, "section_insertion") == 0) {
        method_config.method_type = SECTION_INSERTION_METHOD;
        if (elf_insert_section(elf) == -1) {
            log_error("Error during Section insertion");
            return -1;
        }
    }
    else if (strcmp(packer_config.packing_method, "code_cave") == 0) {
        method_config.method_type = CODE_CAVE_METHOD;
        if (elf_code_cave_injection(elf) == -1) {
            log_error("Error during Code Cave Injection");
            return -1;
        }
    }
    return 1;
}