#pragma once

#include <sodium.h>

typedef union {
    uint8_t bytes[crypto_sign_PUBLICKEYBYTES];
    uint64_t octets[crypto_sign_PUBLICKEYBYTES / sizeof(uint64_t)];
} public_key_t;

typedef union {
    uint8_t bytes[crypto_sign_SECRETKEYBYTES];
    struct {
        uint8_t seed[crypto_sign_SEEDBYTES];
        public_key_t pk;
    } parts;
} private_key_t;
