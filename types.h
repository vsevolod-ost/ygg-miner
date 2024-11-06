#pragma once

#include <sodium.h>

#define DEFTYPEOFSIZE(name, size) \
    typedef struct {              \
        uint8_t as_bytes[size];   \
    } name

DEFTYPEOFSIZE(public_key_t, crypto_sign_PUBLICKEYBYTES);
DEFTYPEOFSIZE(secret_key_t, crypto_sign_SECRETKEYBYTES);

#undef DEFTYPEOFSIZE

typedef struct {
    public_key_t pk;
    secret_key_t sk;
} keypair_t;
