#include "pe_writing.h"
#include "pe_allocation.h"
#include "file_functions.h"
#include "helper.h"
#include <unistd.h>
#include <errno.h>

static long calc_checksum(const char* buffer, size_t buffer_size, size_t checksumOffset) {
    if (!buffer || !buffer_size) return 0;

    const unsigned short* wordsBuff = reinterpret_cast<const unsigned short*>(buffer);
    const size_t wordsCount = buffer_size / sizeof(unsigned short);
    const size_t remainingBytes = buffer_size % sizeof(unsigned short);

    size_t checksumBgn = checksumOffset;
    size_t checksumEnd = checksumBgn + sizeof(uint32_t);

    const long long maxVal = ((long long)1) << 32;
    long long checksum = 0;
    for (int i = 0; i < wordsCount; i++) {
        unsigned short chunk = wordsBuff[i];

        size_t bI = i * sizeof(unsigned short);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(unsigned short);
            size_t shift = (sizeof(unsigned short) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }
        checksum = (checksum & 0xffffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }

    //handle remaining bytes
    if (remainingBytes > 0) {
        unsigned short chunk = 0;
        memcpy(&chunk, buffer + wordsCount * sizeof(unsigned short), remainingBytes);

        size_t bI = wordsCount * sizeof(unsigned short);
        if (checksumBgn != checksumEnd && bI > checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(unsigned short);
            size_t shift = (sizeof(unsigned short) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }
        checksum = (checksum & 0xfffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xfffffff) + (checksum >> 32);
        }
    }
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum)+(checksum >> 16);
    checksum = checksum & 0xffff;
    checksum += buffer_size;
    return checksum;
}

static int set_new_checksum(char* filename, size_t checksumOffset, size_t fileOffset) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        log_error("open() failure: %s", strerror(errno));
        return -1;
    }
    size_t file_data_size = lseek(fd, 0, SEEK_END);
    if (file_data_size < 0) {
        close(fd);
        log_error("lseek() failure: %s", strerror(errno));
        return -1;
    }
    char* file_data = (char*)malloc(file_data_size);
    if (file_data == NULL) {
        log_error("Memory allocation failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        log_error("lseek() failure to reset position: %s", strerror(errno));
        free(file_data);
        close(fd);
        return -1;
    }

    ssize_t n_bytes = read(fd, file_data, file_data_size);
    if (n_bytes < 0) {
        perror("read error");
        free(file_data); // Don't forget to free allocated memory in case of error
        return -1;
    }
    close(fd);
    checksumOffset += fileOffset;
    uint32_t checksum = calc_checksum(file_data, file_data_size, checksumOffset);
    log_info("checksum: 0x%x", checksum);
    memcpy(file_data + checksumOffset, &checksum, sizeof(checksum));
    fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0755); // NOLINT(hicpp-signed-bitwise)
    if (fd < 0) {
        log_error("open() failure: %s", strerror(errno));
        return -1;
    }
    if ((n_bytes = write(fd, file_data, file_data_size)) != file_data_size) {
        log_error("write() failure: %s", strerror(errno));
        return -1;
    }
    close(fd);
    free(file_data);
}


int write_pe(t_pe* pe, char* filename) {
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0755); // NOLINT(hicpp-signed-bitwise)
    if (fd < 0) {
        log_error("open() failure: %s", strerror(errno));
        return -1;
    }
    log_verbose("Writing DOS header ...");
    size_t checksumOffset{};
    size_t fileOffset{};
    if (pe->s_type == PE32) {
        write_to_file(fd, ((t_pe32*)pe)->dos_header, sizeof(IMAGE_DOS_HEADER));

        log_verbose("Writing DOS Stub ...");
        write_to_file(fd, ((t_pe32*)pe)->dos_stub, ((t_pe32*)pe)->dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));

        log_verbose("Writing PE header ...");
        write_to_file(fd, ((t_pe32*)pe)->pe_header, sizeof(IMAGE_NT_HEADERS32));

        log_verbose("Writing Sections headers ...");
        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            write_to_file(fd, &(((t_pe32*)pe)->section_header[i]), sizeof(IMAGE_SECTION_HEADER));
        }
        add_zero_padding(fd, ((t_pe32*)pe)->section_header[0].PointerToRawData);

        log_verbose("Writing Sections data ...");
        for (int i = 0; i < ((t_pe32*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            write_to_file(fd, ((t_pe32*)pe)->section_data[i], ((t_pe32*)pe)->section_header[i].SizeOfRawData);
        }

        if (((t_pe32*)pe)->overlay != NULL) {
            log_verbose("Writting Overlay data ...");
            write_to_file(fd, ((t_pe32*)pe)->overlay, ((t_pe64*)pe)->overlay_size);
        }
        checksumOffset = (char*)&((t_pe32*)pe)->pe_header->OptionalHeader.CheckSum - (char*)((t_pe32*)pe)->pe_header;
        fileOffset = (size_t)((t_pe32*)pe)->dos_header->e_lfanew;
    }
    else {
        write_to_file(fd, ((t_pe64*)pe)->dos_header, sizeof(IMAGE_DOS_HEADER));

        log_verbose("Writing DOS Stub ...");
        write_to_file(fd, ((t_pe64*)pe)->dos_stub, ((t_pe64*)pe)->dos_header->e_lfanew - sizeof(IMAGE_DOS_HEADER));

        log_verbose("Writing PE header ...");
        write_to_file(fd, ((t_pe64*)pe)->pe_header, sizeof(IMAGE_NT_HEADERS64));

        log_verbose("Writing Sections headers ...");
        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            write_to_file(fd, &(((t_pe64*)pe)->section_header[i]), sizeof(IMAGE_SECTION_HEADER));
            uint32_t PtrToRawData = ((t_pe64*)pe)->section_header[i].PointerToRawData;
        }
        add_zero_padding(fd, ((t_pe64*)pe)->section_header[0].PointerToRawData);

        log_verbose("Writing Sections data ...");
        for (int i = 0; i < ((t_pe64*)pe)->pe_header->FileHeader.NumberOfSections; i++) {
            write_to_file(fd, ((t_pe64*)pe)->section_data[i], ((t_pe64*)pe)->section_header[i].SizeOfRawData);
        }

        if (((t_pe64*)pe)->overlay != NULL) {
            log_verbose("Writting Overlay data ...");
            write_to_file(fd, ((t_pe64*)pe)->overlay, ((t_pe64*)pe)->overlay_size);
        }
        checksumOffset = (char*)&((t_pe64*)pe)->pe_header->OptionalHeader.CheckSum - (char*)((t_pe64*)pe)->pe_header;
        fileOffset = (size_t)((t_pe64*)pe)->dos_header->e_lfanew;
    }
    close(fd);
    return 1;
}