#include <string>
#include <sys/mman.h>

#include "helper.h"
#include "file_functions.h"
#include "packer_config.h"
#include "elf_packing.h"
#include "pe_packing.h"
#include "packing_method.h"

struct method_config method_config;

static std::string getPatchedFilename(const std::string& fileName) {
    size_t dotPos = fileName.rfind('.');
    if (dotPos != std::string::npos) {
        std::string base = fileName.substr(0, dotPos);
        std::string ext = fileName.substr(dotPos);
        return base + "_patched" + ext;
    }
    else {
        return fileName + "_patched";
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        //log_error("Usage: %s <input_file>", argv[0]);
        log_error("Usage: %s <method> <input_file>", argv[0]);
        log_info("method ?");
        log_verbose("\t1: section_insertion");
        log_verbose("\t2: code_cave");
        return 1;
    }

    std::string filePath = argv[2];
    //std::string filePath = "Autoruns.exe";
    //std::string filePath = "cccc.exe";
    std::string packing_method = argv[1];
    //std::string packing_method = "section_insertion";
    //std::string packing_method = "code_cave";
    std::string outputFilename = getPatchedFilename(filePath);

    void* file_data{};
    size_t file_data_size{};
    log_info("Allocating file in memory ...");
    if (allocate_file(filePath.data(), &file_data, &file_data_size) == -1) {
        log_error("Error during file allocation");
        return -1;
    }
    int file_type = check_magic_bytes((char*)file_data, file_data_size);
    if (file_type == ELF_FILE) {
        int arch = get_elf_arch((char*)file_data, file_data_size);
        if (arch == UNKNOWN_ARCH) {
            munmap(file_data, file_data_size);
            log_error("Couldn't detect the architecture of the file");
            return -1;
        }
        if (fill_packer_config(packing_method.c_str(), arch, file_type, filePath) == -1) {
            munmap(file_data, file_data_size);
            log_error("Error during packer configuration");
            return -1;
        }
        int p_status = pack_elf(filePath.data(), (char*)file_data, file_data_size, outputFilename.data());
        if (p_status == -1) {
            log_error("An error occured during the ELF packing");
        }
    }
    else if (file_type == PE_FILE) {
        int arch = get_pe_arch((char*)file_data, file_data_size);
        if (arch == UNKNOWN_ARCH) {
            munmap(file_data, file_data_size);
            log_error("Couldn't detect the architecture of the file");
            return -1;
        }

        if (fill_packer_config(packing_method.c_str(), arch, file_type, filePath) == -1) {
            munmap(file_data, file_data_size);
            log_error("Error during packer configuration");
            return -1;
        }

        int p_status = pack_pe(filePath.data(), (char*)file_data, file_data_size, outputFilename.data());
        if (p_status == -1) {
            log_error("An error occured during the PE packing");
        }
    }
    else {
        log_error("Invalid file type");
        munmap(file_data, file_data_size);
    }
    return 0;
}
