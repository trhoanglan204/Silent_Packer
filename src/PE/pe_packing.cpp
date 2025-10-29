#include "pe_packing.h"
#include "pe_allocation.h"
#include "pe_deallocation.h"
#include "file_functions.h"
#include "packer_config.h"
#include "pe_writing.h"
#include "pe_packing_method.h"
#include "pe_encryption.h"
#include "helper.h"
#include <sys/mman.h>
#include <string>

static void log_arch(s_packer_config& packer, char* file_name, char* file_data) {
    int subsys = get_pe_subsystem(file_data, packer_config.bit);

    const char* display_bits = "";
    const char* display_subsystem = "";
    const char* display_arch = "";
    const char* display_type = "";
    if (isExecutable(file_data, packer.bit)) {
        display_type = "executable";
        if (isDLL(file_data, packer.bit)) {
            display_type = "executable (DLL)";
        }
    }
    else {
        display_type = "Unknown type";
    }
    switch (subsys) {
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
        display_subsystem = "(console)";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
        display_subsystem = "(GUI)";
        break;
    case IMAGE_SUBSYSTEM_NATIVE:
        display_subsystem = "(native)";
        break;
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
        display_subsystem = "(boot application)";
        break;
    default:
        display_subsystem = "(unkown)";
        break;
    }
    switch (packer.bit) {
    case x32_ARCH:
        display_bits = "PE32";
        break;
    case x64_ARCH:
        display_bits = "PE32+";
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
        display_arch = "ARM";
        break;
    case x64_ARM:
        display_arch = "ARM64";
        break;
    }
    std::string display = std::string(file_name) + ": " +
        display_bits + " " +
        display_type + " " +
        display_subsystem + " " +
        display_arch + ", for MS Windows";
    log_verbose(display.c_str());
}

int pack_pe(char* file, char* file_data, size_t file_data_size, char* output) {
    log_arch(packer_config, file, file_data);
    if (packer_config.arch == x32_ARM || packer_config.arch == x64_ARM) {
        log_error("Not support Win ARM yet");
        return -1;
    }
    log_info("Allocating PE in memory ...");

    t_pe* pe = NULL;
    if (allocate_pe(&pe, file_data, file_data_size, packer_config.arch) == -1) {
        munmap(file_data, file_data_size);
        log_error("Error during PE allocation");
        return -1;
    }

    // De-allocate mapped file as we don't need it anymore
    munmap(file_data, file_data_size);

    log_info("Encrypting .text section ...");
    if (encrypt_pe(pe) == -1) {
        deallocate_pe(pe);
        log_error("Error during PE encryption");
        return -1;
    }

    log_info("Packing using specified method ...");
    if (pe_pack_using_method(pe) == -1) {
        deallocate_pe(pe);
        log_error("Error during PE packing");
        return -1;
    }

    log_info("Writing Packed PE to file ...");
    if (write_pe(pe, output) == -1) {
        deallocate_pe(pe);
        log_error("Error during new PE writing");
        return -1;
    }

    log_success("File %s packed into %s !", file, output);
    deallocate_pe(pe);

    return 1;
}