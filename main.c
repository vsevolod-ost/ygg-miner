/*
 * ygg-miner: searches for Yggdrasil keys whose IPv6 address (or /64 subnet)
 * is "better" than the ones found so far: higher, shorter or matching a pattern.
 * Prints one key per line: "<address>\t<private key>".
 */

/* be64toh, clock_gettime, getopt */
#define _DEFAULT_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
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
/* Keys a mining thread generates between checks of statistics requests and publishing its key count */
#define BATCH_SIZE 256

static struct {
	bool print_all;
	char const *regexpr_s;
	bool subnet;
	bool length;
} config;

static struct {
	regex_t regexpr;
	struct timespec start_time;

	/* Written only in the "best" critical section; read outside it for the cheap rejection and statistics */
	atomic_int best_height;
	atomic_int best_length;
	atomic_uint_fast64_t keys_generated;
} globals;

/* Set from signal handlers: lock-free atomics are async-signal-safe */
static atomic_int shutdown_signal;
static atomic_bool stats_requested;
static_assert(ATOMIC_INT_LOCK_FREE == 2 && ATOMIC_BOOL_LOCK_FREE == 2, "signal flags must be lock-free");

static void handle_shutdown(int sig)
{
	/* Second signal terminates immediately */
	if (atomic_exchange(&shutdown_signal, sig)) {
		signal(sig, SIG_DFL);
		raise(sig);
	}
}

static void handle_stats(int sig)
{
	(void)sig;
	atomic_store(&stats_requested, true);
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

static void print_stats(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	double const elapsed =
	    (now.tv_sec - globals.start_time.tv_sec) + (now.tv_nsec - globals.start_time.tv_nsec) / 1e9;
	uint64_t const keys = atomic_load_explicit(&globals.keys_generated, memory_order_relaxed);

	char best[64] = "";
	if (config.length)
		snprintf(best, sizeof best, ", best length %d",
			 atomic_load_explicit(&globals.best_length, memory_order_relaxed));
	if (!config.print_all) {
		size_t const used = strlen(best);
		snprintf(best + used, sizeof best - used, ", best height %d",
			 atomic_load_explicit(&globals.best_height, memory_order_relaxed));
	}

	fprintf(stderr, "%" PRIu64 " keys in %.0f s, %ld KH/s%s\n", keys, elapsed, lround(keys / elapsed / 1000), best);
}

/*
 * Decides whether a key with the given address length and height beats the best one and records it.
 * With -l a shorter address always wins and resets the height race; otherwise a higher key wins.
 * Must be called inside the "best" critical section.
 */
static bool update_best(int length, int height)
{
	if (config.length) {
		int const best_length = atomic_load_explicit(&globals.best_length, memory_order_relaxed);
		if (length > best_length)
			return false;
		if (length < best_length) {
			atomic_store_explicit(&globals.best_length, length, memory_order_relaxed);
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

	char addr_s[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &addr, addr_s, sizeof addr_s);

	if (config.regexpr_s && regexec(&globals.regexpr, addr_s, 0, NULL, 0) != 0)
		return;

	char private_key_hex[sizeof key->bytes * 2 + 1];
	sodium_bin2hex(private_key_hex, sizeof private_key_hex, key->bytes, sizeof key->bytes);

	/* Updating the best key and printing it in one critical section keeps the output in order of improvement */
#pragma omp critical(best)
	if (update_best(strlen(addr_s), height))
		printf("%s\t%s\n", addr_s, private_key_hex);

	sodium_memzero(private_key_hex, sizeof private_key_hex);
}

static void mine(void)
{
#pragma omp parallel
	{
		private_key_t key;

		while (!atomic_load_explicit(&shutdown_signal, memory_order_relaxed)) {
			for (unsigned i = 0; i < BATCH_SIZE; ++i) {
				gen_private_key(&key);
				try_key(&key);
			}
			atomic_fetch_add_explicit(&globals.keys_generated, BATCH_SIZE, memory_order_relaxed);

			if (atomic_load_explicit(&stats_requested, memory_order_relaxed) &&
			    atomic_exchange(&stats_requested, false))
				print_stats();
		}

		sodium_memzero(&key, sizeof key);
	}
}

static void print_usage(FILE *stream, char const *program)
{
	fprintf(stream,
		"Usage: %s [-a] [-3] [-l] [-g REGEX]\n"
		"Mine Yggdrasil keys and print every key that beats the best one found so far,\n"
		"one per line: <address> TAB <private key>.\n"
		"\n"
		"  -a        print every key passing the filters, not only improvements\n"
		"  -3        work with /64 subnets (300::/8) instead of addresses\n"
		"  -l        prefer the shortest address text, then the highest one\n"
		"  -g REGEX  print only addresses matching the POSIX extended REGEX\n"
		"  -h        show this help\n"
		"\n"
		"Threads: OMP_NUM_THREADS (default: all CPUs). Statistics: send SIGUSR1.\n"
		"Stops on SIGINT/SIGTERM, a second one exits immediately.\n",
		program);
}

int main(int argc, char *argv[])
{
	for (int opt; (opt = getopt(argc, argv, "a3lg:h")) != -1;) {
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
		case '3':
			config.subnet = true;
			break;
		case 'l':
			config.length = true;
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

	struct sigaction sa = {.sa_handler = handle_shutdown};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = handle_stats;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &sa, NULL);

	/* The mask is inherited from the parent, which may block these; threads created later inherit ours */
	sigset_t handled;
	sigemptyset(&handled);
	sigaddset(&handled, SIGINT);
	sigaddset(&handled, SIGTERM);
	sigaddset(&handled, SIGUSR1);
	sigprocmask(SIG_UNBLOCK, &handled, NULL);

	/* Found keys are rare: flush every record even when stdout is a pipe or a file */
	setvbuf(stdout, NULL, _IOLBF, 0);

	atomic_init(&globals.best_height, -1);
	atomic_init(&globals.best_length, INET6_ADDRSTRLEN);
	clock_gettime(CLOCK_MONOTONIC, &globals.start_time);

	mine();

	if (config.regexpr_s)
		regfree(&globals.regexpr);

	/* Die by the signal that stopped us, so the caller sees the conventional status (130 for Ctrl+C) */
	int const sig = atomic_load(&shutdown_signal);
	fflush(stdout);
	signal(sig, SIG_DFL);
	raise(sig);
	return EXIT_FAILURE;
}
