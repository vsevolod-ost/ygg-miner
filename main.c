#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <math.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include <omp.h>
#include <sodium.h>

#include "config.h"
#include "types.h"

void handle_sigint(int sig)
{
    exit(0);
}

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
#define U64_IN_PK sizeof(public_key_t) / sizeof(uint64_t)
    static_assert(sizeof(public_key_t) % sizeof(uint64_t) == 0, "");
    union {
        public_key_t as_key;
        uint64_t as_ints[U64_IN_PK];
        uint8_t as_bytes[sizeof(public_key_t)];
    } inv_key;
    inv_key.as_key = *key;

    for (size_t i = 0; i < U64_IN_PK; ++i)
        inv_key.as_ints[i] = ~inv_key.as_ints[i];
#undef U64_IN_PK

    int total_bit_offset = key_height + 1;
    int byte_offset = total_bit_offset / 8;
    int bit_offset = total_bit_offset % 8;

    uint8_t* addr_bytes = addr->__in6_u.__u6_addr8;
    addr_bytes[0] = 2;
    addr_bytes[1] = key_height;
    for (size_t i = 2; i < sizeof(struct in6_addr); ++i) {
        uint8_t cur_byte = inv_key.as_bytes[byte_offset],
                next_byte = inv_key.as_bytes[byte_offset + 1];
        addr_bytes[i] = (cur_byte << bit_offset) | (next_byte >> (8 - bit_offset));
        ++byte_offset;
    }
}

void print_key_info(keypair_t* keypair, int height)
{
    /* IP address */
    struct in6_addr addr;
    keytoaddr(&addr, &keypair->pk, height);
    char addr_s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &addr, addr_s, sizeof addr_s);

    /* Private key */
    char secret_key_hex[sizeof(secret_key_t) * 2 + 1];
    sodium_bin2hex(secret_key_hex, sizeof secret_key_hex, keypair->sk.as_bytes, sizeof(secret_key_t));

    printf("# IPv6 address: %s\nPrivateKey: %s\n", addr_s, secret_key_hex);
}

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        perror("Sodium library couldn't be initialized\n");
        return 1;
    }

    signal(SIGINT, handle_sigint);

    bool option_print_all = false;
    for (int opt; (opt = getopt(argc, argv, "a")) != -1;) {
        if (opt == 'a')
            option_print_all = true;
    }

#if MEASURE_SPEED
    atomic_uint_fast64_t counter = 0;
    typedef _Atomic(time_t) atomic_time_t;
    struct {
        atomic_time_t time;
        uint64_t count;
    } progress = { time(NULL), counter };
#endif /* MEASURE_SPEED */

    atomic_int_fast16_t best_height = -1;

#pragma omp parallel for
    for (uint64_t __i = 0; __i < UINT64_MAX; ++__i) {
        /* Generate keypair*/
        keypair_t keypair;
        gen_keypair(&keypair);

        /* Count address height*/
        const int height = get_leading_zero_bits(&keypair.pk);

        /* Print result if it is the best one */
        if (option_print_all)
            print_key_info(&keypair, height);
        else {
            for (int_fast16_t best_height_copy; height > (best_height_copy = best_height);) {
                if (atomic_compare_exchange_weak(&best_height, &best_height_copy, height)) {
                    print_key_info(&keypair, height);
                    break;
                }
            }
        }

#if MEASURE_SPEED
        time_t now = time(NULL),
               progress_time_copy = progress.time,
               time_delta = now - progress_time_copy;
        if (time_delta >= 5 && atomic_compare_exchange_strong(&progress.time, &progress_time_copy, now)) {
            uint64_t counter_copy = counter;
            uint64_t count_delta = counter_copy - progress.count;

            int speed = round((double)count_delta / (double)time_delta / 1000.);
            fprintf(stderr, "Speed: %dK keys per second\n", speed);

            progress.count = counter_copy;
        }

        atomic_fetch_add(&counter, 1);
#endif /* MEASURE_SPEED */
    }
}
