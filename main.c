/*
 * ygg-miner: searches for Yggdrasil keys whose IPv6 address (or /64 subnet)
 * is "better" than the ones found so far: higher, shorter or matching a pattern.
 */

/* be64toh, clock_gettime, getopt */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbit.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <omp.h>
#include <regex.h>
#include <sodium.h>

#include "types.h"

/* Yggdrasil subnet prefix length in bytes (300::/8 + 56 bits of the key = /64) */
#define SUBNET_SIZE 8
/* Interval of speed reports, seconds */
#define MEASURE_SPEED_TIME 10
/* Keys a mining thread generates before publishing its count to the speed counter */
#define SPEED_COUNTER_BATCH 256

static struct {
	bool print_all;
	char const *regexpr_s;
	bool measure_speed;
	bool subnet;
	bool length;
	int threads;
} config;

static struct {
	regex_t regexpr;
	struct in6_addr brute_addr;
	size_t brute_bytes_count;

	/* Written only in the "best" critical section; read outside it for the cheap rejection */
	atomic_int best_height;
	int best_length;
	atomic_uint_fast64_t keys_generated;
} globals;

static volatile sig_atomic_t shutdown_requested;

static void graceful_shutdown(int sig)
{
	(void)sig;
	/* Second Ctrl+C terminates immediately */
	if (shutdown_requested)
		_exit(EXIT_FAILURE);
	shutdown_requested = 1;
}

static void gen_private_key(private_key_t *key)
{
	uint8_t pk_buf[crypto_sign_PUBLICKEYBYTES];
	crypto_sign_ed25519_keypair(pk_buf, key->bytes);
}

/* Number of leading zero bits of the public key (the "height" of the address) */
static int get_leading_zero_bits(public_key_t const *key)
{
	int zero_bits = 0;
	for (size_t i = 0; i < sizeof key->octets / sizeof *key->octets; ++i) {
		/* Key bytes are big-endian: the first byte holds the most significant bits */
		uint64_t const octet = be64toh(key->octets[i]);
		zero_bits += stdc_leading_zeros(octet);
		if (octet)
			break;
	}
	return zero_bits;
}

static uint8_t key_byte(public_key_t const *key, size_t index)
{
	return index < sizeof key->bytes ? key->bytes[index] : 0;
}

/* Yggdrasil address: 0x02, height, then the inverted key bits following the leading zeros and the first one */
static void keytoaddr(struct in6_addr *addr, public_key_t const *key, int key_height)
{
	size_t const total_bit_offset = key_height + 1;
	size_t byte_offset = total_bit_offset / CHAR_BIT;
	unsigned const bit_offset = total_bit_offset % CHAR_BIT;

	uint8_t *addr_bytes = addr->s6_addr;
	addr_bytes[0] = 2;
	addr_bytes[1] = key_height;
	for (size_t i = 2; i < sizeof addr->s6_addr; ++i, ++byte_offset) {
		uint8_t const left_byte = ~key_byte(key, byte_offset);
		uint8_t const right_byte = ~key_byte(key, byte_offset + 1);
		addr_bytes[i] = (left_byte << bit_offset) | (right_byte >> (CHAR_BIT - bit_offset));
	}
}

/* Turns an address into its /64 subnet in place: 0x03 prefix, host part zeroed */
static void addr_to_subnet(struct in6_addr *addr)
{
	addr->s6_addr[0] = 3;
	memset(addr->s6_addr + SUBNET_SIZE, 0, sizeof addr->s6_addr - SUBNET_SIZE);
}

static bool is_brute_target(struct in6_addr const *addr)
{
	/* The first byte (0x02 / 0x03) only tells an address from a subnet */
	return memcmp(addr->s6_addr + 1, globals.brute_addr.s6_addr + 1, globals.brute_bytes_count) == 0;
}

static void *speed_thread_run(void *arg)
{
	(void)arg;
	struct timespec last;
	clock_gettime(CLOCK_MONOTONIC, &last);

	while (!shutdown_requested) {
		sleep(MEASURE_SPEED_TIME);
		/* sleep() is cut short by the shutdown signal: don't report a partial interval */
		if (shutdown_requested)
			break;

		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		uint64_t const keys = atomic_exchange_explicit(&globals.keys_generated, 0, memory_order_relaxed);
		double const elapsed = (now.tv_sec - last.tv_sec) + (now.tv_nsec - last.tv_nsec) / 1e9;
		last = now;

		fprintf(stderr, "Speed: %ld KH/s\n", lround(keys / elapsed / 1000));
	}
	return NULL;
}

/*
 * Decides whether a key with the given address length and height beats the best one and records it.
 * With -l a shorter address always wins and resets the height race; otherwise a higher key wins.
 * Must be called inside the "best" critical section.
 */
static bool update_best(int length, int height)
{
	if (config.length) {
		if (length > globals.best_length)
			return false;
		if (length < globals.best_length) {
			globals.best_length = length;
			atomic_store_explicit(&globals.best_height, -1, memory_order_relaxed);
		}
	}

	if (!config.print_all) {
		if (height <= atomic_load_explicit(&globals.best_height, memory_order_relaxed))
			return false;
		atomic_store_explicit(&globals.best_height, height, memory_order_relaxed);
	}

	return true;
}

static void try_key(private_key_t const *key)
{
	int const height = get_leading_zero_bits(&key->parts.pk);

	/* Cheap rejection before the address is built */
	if (!config.print_all && !config.length &&
	    height <= atomic_load_explicit(&globals.best_height, memory_order_relaxed))
		return;

	struct in6_addr addr;
	keytoaddr(&addr, &key->parts.pk, height);
	if (config.subnet)
		addr_to_subnet(&addr);

	if (globals.brute_bytes_count && !is_brute_target(&addr))
		return;

	char addr_s[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, addr_s, sizeof addr_s);

	if (config.regexpr_s && regexec(&globals.regexpr, addr_s, 0, NULL, 0) != 0)
		return;

	char private_key_hex[sizeof key->bytes * 2 + 1];
	sodium_bin2hex(private_key_hex, sizeof private_key_hex, key->bytes, sizeof key->bytes);

	/* Updating the best key and printing it in one critical section keeps the output in order of improvement */
#pragma omp critical(best)
	if (update_best(strlen(addr_s), height))
		printf("# %s: %s\nPrivateKey: %s\n", config.subnet ? "IPv6 subnet" : "IPv6 address", addr_s,
		       private_key_hex);

	sodium_memzero(private_key_hex, sizeof private_key_hex);
}

static void mine(void)
{
#pragma omp parallel
	{
		private_key_t key;
		unsigned batch = 0;

		while (!shutdown_requested) {
			gen_private_key(&key);
			try_key(&key);

			if (config.measure_speed && ++batch == SPEED_COUNTER_BATCH) {
				atomic_fetch_add_explicit(&globals.keys_generated, batch, memory_order_relaxed);
				batch = 0;
			}
		}

		sodium_memzero(&key, sizeof key);
	}
}

static void print_usage(FILE *stream, char const *program)
{
	fprintf(stream,
		"Usage: %s [options]\n"
		"Mine Yggdrasil keys and print every key that beats the best one found so far.\n"
		"\n"
		"Options:\n"
		"  -a          print every key passing the filters, not only improvements\n"
		"  -3          work with /64 subnets (300::/8) instead of addresses\n"
		"  -l          prefer the shortest address text, then the highest one\n"
		"  -g REGEX    print only addresses matching the POSIX extended REGEX\n"
		"  -b ADDR     look for the key of exactly this address (2xx::) or subnet (3xx::); implies -a\n"
		"  -t THREADS  number of mining threads (default: all CPUs)\n"
		"  -s          report the mining speed to stderr every %d seconds\n"
		"  -h          show this help\n"
		"\n"
		"Stop with Ctrl+C; press it twice to exit immediately.\n",
		program, MEASURE_SPEED_TIME);
}

static bool parse_brute_addr(char const *addr_s)
{
	if (inet_pton(AF_INET6, addr_s, &globals.brute_addr) != 1) {
		fprintf(stderr, "Invalid IPv6 address: %s\n", addr_s);
		return false;
	}

	switch (globals.brute_addr.s6_addr[0]) {
	case 2:
		globals.brute_bytes_count = sizeof globals.brute_addr.s6_addr - 1;
		break;
	case 3:
		globals.brute_bytes_count = SUBNET_SIZE - 1;
		config.subnet = true;
		break;
	default:
		fprintf(stderr, "Invalid Yggdrasil address %s: it should start with 2xx: or 3xx:\n", addr_s);
		return false;
	}

	config.print_all = true;
	return true;
}

static bool parse_threads(char const *threads_s)
{
	char *end;
	errno = 0;
	long const threads = strtol(threads_s, &end, 10);
	if (errno || end == threads_s || *end || threads < 1 || threads > INT_MAX) {
		fprintf(stderr, "Invalid threads count: %s\n", threads_s);
		return false;
	}
	config.threads = threads;
	return true;
}

int main(int argc, char *argv[])
{
	for (int opt; (opt = getopt(argc, argv, "as3lg:b:t:h")) != -1;) {
		switch (opt) {
		case 'a':
			config.print_all = true;
			break;
		case 'g':
			config.regexpr_s = optarg;
			if (regcomp(&globals.regexpr, config.regexpr_s, REG_EXTENDED | REG_NOSUB) != 0) {
				fprintf(stderr, "Invalid regular expression: %s\n", config.regexpr_s);
				return EXIT_FAILURE;
			}
			break;
		case 's':
			config.measure_speed = true;
			break;
		case 'b':
			if (!parse_brute_addr(optarg))
				return EXIT_FAILURE;
			break;
		case '3':
			config.subnet = true;
			break;
		case 'l':
			config.length = true;
			break;
		case 't':
			if (!parse_threads(optarg))
				return EXIT_FAILURE;
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		default:
			print_usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
		print_usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	if (sodium_init() < 0) {
		fprintf(stderr, "Sodium library couldn't be initialized\n");
		return EXIT_FAILURE;
	}

	struct sigaction sa = {.sa_handler = graceful_shutdown};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* Found keys are rare: flush every record even when stdout is a pipe or a file */
	setvbuf(stdout, NULL, _IOLBF, 0);

	atomic_init(&globals.best_height, -1);
	globals.best_length = INET6_ADDRSTRLEN;

	if (config.measure_speed) {
		pthread_t speed_thread;
		if (pthread_create(&speed_thread, NULL, speed_thread_run, NULL) != 0) {
			fprintf(stderr, "Couldn't start the speed measuring thread\n");
			return EXIT_FAILURE;
		}
		pthread_detach(speed_thread);
	}

	if (config.threads)
		omp_set_num_threads(config.threads);

	mine();

	if (config.regexpr_s)
		regfree(&globals.regexpr);
	return EXIT_SUCCESS;
}
