#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <omp.h>
#include <regex.h>
#include <sodium.h>

#include "config.h"
#include "types.h"

struct {
    bool print_all;
    char* ip_pattern;
} config;

struct {
    regex_t regexpr;
} globals;

void* flush_thread_run(void* args)
{
    for (;;) {
        sleep(1);
        fflush(stdout);
    }
}

void gen_private_key(private_key_t* key)
{
    static uint8_t pk_buf[crypto_sign_PUBLICKEYBYTES];
    crypto_sign_ed25519_keypair(pk_buf, key->bytes);
}

int get_leading_zero_bits(public_key_t* key)
{
    /* Count zero bytes */
    uint_fast8_t bytes_count = 0;
    while (bytes_count < sizeof(public_key_t) && !key->bytes[bytes_count])
        ++bytes_count;

    /* Count zero bits in first non-zero byte */
    uint8_t non_zero_byte = key->bytes[bytes_count];
    uint_fast8_t bits_count = 8;
    do {
        non_zero_byte >>= 1;
        bits_count -= 1;
    } while (non_zero_byte);

    /* Count total zero bits and return */
    bits_count += bytes_count * 8;
    return bits_count;
}

void keytoaddr(char addr_s[INET6_ADDRSTRLEN], public_key_t* key, int key_height)
{
    int total_bit_offset = key_height + 1;
    int byte_offset = total_bit_offset / 8;
    int bit_offset = total_bit_offset % 8;

    struct in6_addr addr;
    uint8_t* addr_bytes = addr.s6_addr;
    addr_bytes[0] = 2;
    addr_bytes[1] = key_height;
    for (size_t i = 2; i < sizeof(struct in6_addr); ++i) {
        uint8_t cur_byte = ~key->bytes[byte_offset], next_byte = ~key->bytes[byte_offset + 1];
        addr_bytes[i] = (cur_byte << bit_offset) | (next_byte >> (8 - bit_offset));
        ++byte_offset;
    }

    inet_ntop(AF_INET6, &addr, addr_s, INET6_ADDRSTRLEN);
}

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        perror("Sodium library couldn't be initialized\n");
        return 1;
    }

    if (!isatty(STDOUT_FILENO)) {
        pthread_t flush_thread_id;
        pthread_create(&flush_thread_id, NULL, &flush_thread_run, NULL);
    }

    for (int opt; (opt = getopt(argc, argv, "ag:")) != -1;) {
        switch (opt) {
        case 'a':
            config.print_all = true;
            break;
        case 'g':
            config.ip_pattern = optarg;
            if (regcomp(&globals.regexpr, config.ip_pattern, REG_EXTENDED) != 0) {
                perror("Regex compilation failed\n");
                return EXIT_FAILURE;
            }
            break;
        }
    }

    typedef _Atomic(time_t) atomic_time_t;
#if MEASURE_SPEED
    atomic_uint_fast64_t counter = 0;
    struct {
        atomic_time_t time;
        uint64_t count;
    } progress = { time(NULL), counter };
#endif /* MEASURE_SPEED */

    atomic_int_fast16_t best_height = -1;

#pragma omp parallel
    for (;;) {
        /* Generate keypair*/
        private_key_t key;
        gen_private_key(&key);

        /* Count height */
        const int height = get_leading_zero_bits(&key.parts.pk);
        char addr_s[INET6_ADDRSTRLEN] = "";

        for (int_fast16_t best_height_copy; config.print_all || height > (best_height_copy = best_height);) {
            if (!addr_s[0]) {
                keytoaddr(addr_s, &key.parts.pk, height);

                if (config.ip_pattern && regexec(&globals.regexpr, addr_s, 0, NULL, 0) != 0)
                    break;
            }

            if (config.print_all || atomic_compare_exchange_weak(&best_height, &best_height_copy, height)) {
                char private_key_hex[sizeof(private_key_t) * 2 + 1];
                sodium_bin2hex(private_key_hex, sizeof private_key_hex, key.bytes, sizeof(private_key_t));

                printf("# IPv6 address: %s\nPrivateKey: %s\n", addr_s, private_key_hex);
                break;
            }

            fprintf(stderr, "!!!Race!!!\n");
        }

#if MEASURE_SPEED
        time_t now = time(NULL), progress_time_copy = progress.time, time_delta = now - progress_time_copy;
        if (time_delta >= 5 && atomic_compare_exchange_strong(&progress.time, &progress_time_copy, now)) {
            uint64_t counter_copy = counter;
            uint64_t count_delta = counter_copy - progress.count;
            int speed = round((double)count_delta / (double)time_delta / 1000.);
            progress.count = counter_copy;

            fprintf(stderr, "Speed: %d KH/s\n", speed);
        }

        atomic_fetch_add(&counter, 1);
#endif /* MEASURE_SPEED */
    }
}
