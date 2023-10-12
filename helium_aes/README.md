# Verifiable Encryption of AES keys with Helium and Kyber 

This repository contains the implementation of verifiable encryption (VE) from MPC-in-the-head, as described in our paper. 
The basis for the implementation is the [Helium+AES](https://eprint.iacr.org/2022/588) signature scheme, which proves knowledge of an AES key associated with
public plaintext-ciphertext pair. We apply our VE transform using a public-key encryption (PKE) 
scheme based on [Kyber](https://www.pq-crystals.org/kyber/), therefore this implementation allows one to verifiably encrypt an AES key to a Kyber public key. 

## Helium and Kyber implementations
The implementation is based on the publicly available Helium code (https://github.com/IAIK/bnpp_helium_signatures).
In many places the code *signature* refers to the proof in the context of verifiable encryption. (similarly for *sign* and *prove*)

Kyber is the AVX2 version taken from [PQClean](https://github.com/PQClean/PQClean), along with some of the `common` code of
PQClean (main was at `c1b19a865de329e87e9b3e9152362fcb709da8ab` (April 2023) when we took Kyber from PQClean).
The Makefile is modified to build a static library that includes the `common' code from PQClean. 
We added a deterministic version of kem_enc that allows the caller to pass the randomness used for encryption.
We add a variant of KEM decapsulation that makes failures explicit, allowing the caller to check for
decryption failures (see page 14 of the Kyber [spec](https://www.pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf#page=14) for discussion).


## Requirements
Tested on Ubuntu 22.04
C++-17 Compatible Toolchain

For testing and benchmarking:

* [GMP](https://gmplib.org/)
* [NTL](https://shoup.net/ntl)

## Setup
The project uses `cmake`. To build it:
```bash
mkdir build
cd build
cmake ..
make 
# tests (only if you built them.  Use "ccmake ." from the build dir to toggle whether tests are built )
make test
```
To run the verifiable encryption benchmarks (for the `Prove`, `Verify`, `Compress` and `Decrypt` functions),
 you must build the tests, then run 
```
./signature_test  
```

To run some extended benchmarks of the `Prove` and `Verify` functions 
```
python3 ../tools/bench_all.py   # benchmarks a wide range of parameters
./bench_free -i <iterations> <kappa=16> <Sboxes=200> <N> <tau> # benchmark parameters freely; note that (N, tau) should be chose to ensure soundness
```
The benchmark script contains a `SCALING_FACTOR` variable that is used to scale the measured cycles to ms. Configure it according to your specific machine.
