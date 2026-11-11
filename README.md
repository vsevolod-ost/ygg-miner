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
ygg-miner [options]

  -a          print every key passing the filters, not only improvements
  -3          work with /64 subnets (300::/8) instead of addresses
  -l          prefer the shortest address text, then the highest one
  -g REGEX    print only addresses matching the POSIX extended REGEX
  -b ADDR     look for the key of exactly this address (2xx::) or subnet (3xx::); implies -a
  -t THREADS  number of mining threads (default: all CPUs)
  -s          report the mining speed to stderr every 10 seconds
  -h          show this help
```

Every found key is printed as two lines, ready to paste into `yggdrasil.conf`:

```
# IPv6 address: 200:c2ac:65bb:43c4:78d0:4e73:809d:ffad
PrivateKey: c24e8667...
```

Examples:

```sh
ygg-miner -s | tee keys.txt              # highest addresses, with speed reports
ygg-miner -3                             # highest /64 subnets
ygg-miner -l                             # shortest addresses
ygg-miner -a -g ':(cafe|beef):'          # every address with a word in it
```

Stop it with Ctrl+C; a second Ctrl+C exits immediately. Keep the output
private: it contains private keys.

## History

Experiments that did not make it into `main` (lock-free collections, an output
thread on C11 threads, an OpenCL draft) are kept as `archive/*` tags.
