# CMakeList.txt : CMake project for prj, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.19)

### Includes ###
include_directories("${PROJECT_SOURCE_DIR}/includes")
include_directories("${PROJECT_SOURCE_DIR}/includes/ELF")
include_directories("${PROJECT_SOURCE_DIR}/includes/PE")
include_directories("${PROJECT_SOURCE_DIR}/includes/STUB")
include_directories("${PROJECT_SOURCE_DIR}/includes/common")

### Sources ###
set(SOURCES "main.cpp")

set(ELF_SOURCES 
    "ELF/elf_allocation.cpp"
    "ELF/elf_functions.cpp"
    "ELF/elf_packing.cpp"
    "ELF/elf_encryption.cpp"
    "ELF/elf_code_cave.cpp"
    "ELF/elf_section_insertion.cpp"
    "ELF/elf_writing.cpp"
    "ELF/elf_packing_method.cpp"
    "ELF/elf_deallocation.cpp")

set(PE_SOURCES 
    "PE/pe_allocation.cpp"
    "PE/pe_code_cave.cpp"
    "PE/pe_section_insertion.cpp"
    "PE/pe_functions.cpp"
    "PE/pe_packing.cpp"
    "PE/pe_encryption.cpp"
    "PE/pe_writing.cpp"
    "PE/pe_packing_method.cpp"
    "PE/pe_deallocation.cpp")

set(COMMON_SOURCES 
    ${ELF_SOURCES} 
    ${PE_SOURCES}
    "common/file_functions.cpp"
    "common/cipher_functions.cpp"
    "common/loader_functions.cpp"
    "common/packer_config.cpp"
    "common/helper.cpp")

set(SOURCES ${SOURCES} ${COMMON_SOURCES})

# Add source to this project's executable.
add_executable (prj ${SOURCES})

target_link_libraries(prj pthread)
