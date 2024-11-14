#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <math.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <omp.h>
#include <regex.h>
#include <sodium.h>

#include "types.h"

#define SUBNET_SIZE 8
#define MEASURE_SPEED_TIME 10

struct {
    bool print_all;
    char* regexpr_s;
    bool measure_speed;
    char* brute_addr_s;
    bool subnet;
    bool length;
} config;

struct {
    bool shutdown;
    regex_t regexpr;
    struct in6_addr brute_addr;
    size_t brute_bytes_count;
} globals;

void* flush_thread_run(void* args)
{
    for (;;) {
        sleep(1);
        fflush(stdout);
    }
}

void graceful_shutdown(int sig)
{
    if (globals.shutdown)
        exit(EXIT_FAILURE);
    globals.shutdown = true;
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

void keytoaddr(struct in6_addr* addr, public_key_t* key, int key_height)
{
    int total_bit_offset = key_height + 1;
    int byte_offset = total_bit_offset / 8;
    int bit_offset = total_bit_offset % 8;

    uint8_t* addr_bytes = addr->s6_addr;
    addr_bytes[0] = 2;
    addr_bytes[1] = key_height;
    for (size_t i = 2; i < sizeof(struct in6_addr); ++i) {
        uint8_t left_byte = ~key->bytes[byte_offset], right_byte = ~key->bytes[byte_offset + 1];
        addr_bytes[i] = (left_byte << bit_offset) | (right_byte >> (8 - bit_offset));
        ++byte_offset;
    }
}

void addr_to_subnet(struct in6_addr* sub_addr, struct in6_addr* addr)
{
    uint8_t *sub_addr_bytes = sub_addr->s6_addr, *addr_bytes = addr->s6_addr;
    sub_addr_bytes[0] = 3;
    memcpy(sub_addr_bytes + 1, addr_bytes + 1, 8 - 1);
    memset(sub_addr_bytes + 8, 0, 8);
}

bool is_brute_target(struct in6_addr* addr)
{
    uint8_t* brute_bytes = globals.brute_addr.s6_addr;
    uint8_t* addr_bytes = addr->s6_addr;
    return memcmp(addr_bytes + 1, brute_bytes + 1, globals.brute_bytes_count) == 0;
}

void measure_speed(void)
{
    static atomic_uint_fast64_t counter;
    ++counter;

    static _Atomic clock_t last_time;
    if (!last_time)
        last_time = clock();

    clock_t last_time_copy = last_time, now = clock();
    double time_spent = (double)(now - last_time_copy) / (double)CLOCKS_PER_SEC / omp_get_num_threads();
    if (time_spent >= 10 && atomic_compare_exchange_weak(&last_time, &last_time_copy, now)) {
        uint64_t counter_copy;
        do
            counter_copy = counter;
        while (!atomic_compare_exchange_weak(&counter, &counter_copy, 0));

        uint64_t speed = round((counter_copy / time_spent) / 1000.);
        fprintf(stderr, "Speed: %lu KH/s\n", speed);
    }
}

void mine(void)
{
    atomic_int_fast16_t best_height = -1;
    atomic_uint_fast8_t best_length = INET6_ADDRSTRLEN;
#pragma omp parallel
    while (!globals.shutdown) {
        /* Generate keypair*/
        private_key_t key;
        gen_private_key(&key);

        /* Count height */
        const int height = get_leading_zero_bits(&key.parts.pk);

        if (config.print_all || config.length || height > best_height) {
            char addr_s[INET6_ADDRSTRLEN] = "";
            size_t length;
            for (;;) {
                if (!addr_s[0]) {
                    struct in6_addr addr;
                    keytoaddr(&addr, &key.parts.pk, height);
                    if (config.subnet)
                        addr_to_subnet(&addr, &addr);

                    /* Bruteforce*/
                    if (globals.brute_bytes_count && !is_brute_target(&addr))
                        break;

                    inet_ntop(AF_INET6, &addr, addr_s, INET6_ADDRSTRLEN);

                    /* Regex */
                    if (config.regexpr_s && regexec(&globals.regexpr, addr_s, 0, NULL, 0) != 0)
                        break;

                    /* Length */
                    if (config.length)
                        length = strlen(addr_s);
                }

                if (config.length) {
                    uint_fast8_t best_length_copy;
                    if (length > (best_length_copy = best_length))
                        break;

                    if (length < best_length_copy) {
                        if (!atomic_compare_exchange_weak(&best_length, &best_length_copy, length))
                            continue;
                        best_height = -1;
                    }
                }

                if (!config.print_all) {
                    int_fast16_t best_height_copy;
                    if (height <= (best_height_copy = best_height))
                        break;

                    if (!atomic_compare_exchange_weak(&best_height, &best_height_copy, height))
                        continue;
                }

                char private_key_hex[sizeof(private_key_t) * 2 + 1];
                sodium_bin2hex(private_key_hex, sizeof private_key_hex, key.bytes, sizeof(private_key_t));

                /* Print IP address and private key */
                const char* id_name = config.subnet ? "IPv6 subnet" : "IPv6 address";
                printf("# %s: %s\nPrivateKey: %s\n", id_name, addr_s, private_key_hex);
                break;
            }
        }

        if (config.measure_speed)
            measure_speed();
    }
}

int main(int argc, char* argv[])
{
    /* Initialize sodium library */
    if (sodium_init() < 0) {
        perror("Sodium library couldn't be initialized\n");
        return 1;
    }

    /* Configure */
    for (int opt; (opt = getopt(argc, argv, "as3lg:b:")) != -1;) {
        switch (opt) {
        case 'a':
            config.print_all = true;
            break;
        case 'g':
            config.regexpr_s = optarg;
            if (regcomp(&globals.regexpr, config.regexpr_s, REG_EXTENDED) != 0) {
                perror("Regex compilation failed\n");
                return EXIT_FAILURE;
            }
            break;
        case 's':
            config.measure_speed = true;
            break;
        case 'b':
            config.brute_addr_s = optarg;
            if (inet_pton(AF_INET6, config.brute_addr_s, &globals.brute_addr) != 1) {
                perror("Invalid IP address\n");
                return EXIT_FAILURE;
            }
            uint8_t first_byte = globals.brute_addr.s6_addr[0];
            if (first_byte == 3)
                globals.brute_bytes_count = SUBNET_SIZE - 1;
            else if (first_byte == 2)
                globals.brute_bytes_count = sizeof(struct in6_addr) - 1;
            else {
                perror("Invalid IP address: first byte should be 2 or 3\n");
                return EXIT_FAILURE;
            }
            config.print_all = true;
            break;
        case '3':
            config.subnet = true;
            break;
        case 'l':
            config.length = true;
            break;
        default:
            return EXIT_FAILURE;
        }
    }

    /* If stdout is redirected to pipe, manual flush needed */
    if (!isatty(STDOUT_FILENO)) {
        pthread_t flush_thread_id;
        pthread_create(&flush_thread_id, NULL, &flush_thread_run, NULL);
    }

    signal(SIGINT, graceful_shutdown);

    /* Start mine loop */
    mine();
}
