#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
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

void keytoaddr(struct in6_addr* addr, public_key_t* key, int key_height)
{
    /* Invert key */
    public_key_t key_inverted;
    for (size_t i = 0; i < sizeof(public_key_t); ++i)
        key_inverted.as_bytes[i] = ~key->as_bytes[i];

    int total_bit_offset = key_height + 1;
    int byte_offset = total_bit_offset / 8;
    int bit_offset = total_bit_offset % 8;

    uint8_t* addr_bytes = addr->__in6_u.__u6_addr8;
    addr_bytes[0] = 2;
    addr_bytes[1] = key_height;
    for (size_t i = 2; i < sizeof(struct in6_addr); ++i) {
        struct
        {
            uint8_t next_byte;
            uint8_t cur_byte;
        } two_bytes = { key->as_bytes[i - 2 + byte_offset + 1], key->as_bytes[i - 2 + byte_offset + 1] };

        // uint16_t* two_bytes = (uint16_t*)&key->as_bytes[i - 2 + byte_offset];
        addr_bytes[i] = (*(uint16_t*)&two_bytes) << bit_offset >> 8;
    }
}

int main(void)
{
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
                struct in6_addr addr;
                keytoaddr(&addr, &keypair.pk, height);
                char addr_s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &addr, addr_s, sizeof addr_s);
                printf("Address: %s\n", addr_s);
                /* TODO: print private key */
                break;
            }
        }
    }
}
