#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>

#include <omp.h>
#include <sodium.h>

#include "types.h"

void gen_keypair(keypair_t* keypair)
{
    crypto_sign_ed25519_keypair(keypair->pk.as_bytes, keypair->sk.as_bytes);
}

int get_leading_zero_bits(public_key_t* key)
{
    /* Count zero bytes */
    uint_fast8_t bytes = 0;
    while (bytes < sizeof(public_key_t) && !key->as_bytes[bytes])
        ++bytes;

    /* Count zero bits in first non-zero byte */
    uint8_t non_zero_byte = key->as_bytes[bytes];
    uint_fast8_t bits = 8;
    do {
        non_zero_byte >>= 1;
        bits -= 1;
    } while (non_zero_byte);

    /* Count total zero bits and return */
    bits += bytes * 8;
    return bits;
}

int main(void)
{
    assert(sizeof(public_key_t) * 8 <= INT16_MAX);

    if (sodium_init() < 0) {
        perror("Sodium library couldn't be initialized\n");
        return 1;
    }

    atomic_int_fast16_t best_height = -1;

#pragma omp parallel for
    for (uint64_t counter = 0; counter < UINT64_MAX; ++counter) {
        /* Generate keypair*/
        keypair_t keypair;
        gen_keypair(&keypair);

        /* Count address height*/
        int height = get_leading_zero_bits(&keypair.pk);

        /* Save result if it is the best one */
        for (int_fast16_t best_height_copy; height > (best_height_copy = best_height);) {
            if (atomic_compare_exchange_weak(&best_height, &best_height_copy, height)) {
                printf("New best key height is %d\n", height);
                /* TODO: print address and private key */
                break;
            }
        }
    }
}
