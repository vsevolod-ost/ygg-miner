# ygg-miner

A multithreaded miner of [Yggdrasil](https://yggdrasil-network.github.io/) keys.
It generates ed25519 key pairs and prints the ones whose IPv6 address (or /64
subnet) is "better" than everything found so far: higher (more leading zero
bits in the public key, so the address starts with `200:`, `201:`, ...),
shorter, or matching a regular expression.

## Building

Requirements: a C23 compiler (GCC 14+ or Clang 18+) with OpenMP, glibc 2.39+,
CMake 3.21+, pkg-config and libsodium.

```sh
cmake -S . -B build -G Ninja      # Release by default
cmake --build build
```

`-DYGG_MINER_NATIVE=ON` adds `-march=native` (faster, but runs only on CPUs like the build host).

## Usage

```
ygg-miner [-a] [-3] [-l] [-g REGEX]

  -a        print every key passing the filters, not only improvements
  -3        work with /64 subnets (300::/8) instead of addresses
  -l        prefer the shortest address text, then the highest one
  -g REGEX  print only addresses matching the POSIX extended REGEX
  -h        show this help
```

Every found key is one line: the address (or subnet), a tab, and the private
key in hex. Keep the output private: it contains private keys.

```
200:c2ac:65bb:43c4:78d0:4e73:809d:ffad	c24e8667...
```

It is meant to be combined with the usual tools:

```sh
ygg-miner | tee keys.tsv                     # highest addresses as they are found
ygg-miner -3                                 # highest /64 subnets
ygg-miner -l                                 # shortest addresses
ygg-miner -a | grep -m1 ':cafe:'             # first address with a word in it
ygg-miner -a -g ':cafe:' | head -1           # the same, filtered inside the miner (faster)
tail -1 keys.tsv | cut -f2 | sed 's/^/PrivateKey: /'   # line for yggdrasil.conf
```

- Threads: `OMP_NUM_THREADS=4 ygg-miner` (default: all CPUs).
- Statistics: `pkill -USR1 ygg-miner` prints the key count, speed and the best
  result so far to stderr.
- `SIGINT`/`SIGTERM` stop it after the current batch, a second one exits
  immediately. The exit status is that of the signal (130 for Ctrl+C), and a
  closed pipe (`| head -1`) ends it via `SIGPIPE`.

## History

Experiments that did not make it into `main` (lock-free collections, an output
thread on C11 threads, an OpenCL draft) are kept as `archive/*` tags.
