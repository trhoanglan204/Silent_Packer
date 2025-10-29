#include "cipher_functions.h"

uint32_t generate_random_key32() {
    srand(time(NULL));
    uint32_t key = rand();
    return key;
}

uint64_t generate_random_key64() {
    srand(time(NULL));
    uint64_t high = (uint64_t)rand();
    uint64_t low = (uint64_t)rand();
    uint64_t key = (high << 32) | low;
    return key;
}

uint32_t rotate_right32(uint32_t value) {
    uint32_t n_rotations = sizeof(uint32_t);
    uint32_t int_bits = sizeof(uint32_t) * 8;
    return (value >> n_rotations) | (value << (int_bits - n_rotations));
}

uint64_t rotate_right64(uint64_t value) {
    uint64_t n_rotations = sizeof(uint64_t);
    uint64_t int_bits = sizeof(uint64_t) * 8;
    return (value >> n_rotations) | (value << (int_bits - n_rotations));
}

int xor_encrypt32(char* data, size_t data_size, uint32_t key) {
    for (int i = 0; i < (int)data_size; i++) {
        data[i] = (char)(data[i] ^ key);
        key = rotate_right32(key);
    }
    return 1;
}

int xor_encrypt64(char* data, size_t data_size, uint64_t key) {
    for (int i = 0; i < (int)data_size; i++) {
        data[i] = (char)(data[i] ^ key);
        key = rotate_right64(key);
    }
    return 1;
}
