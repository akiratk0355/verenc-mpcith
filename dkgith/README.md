
## Introduction
Implementation of the DKG-in-the-head (DKGitH) and Robust DKG-in-the-head (RDKGitH) verifiable encryption schemes.

## Description
These verifiable encryption (VE) schemes allow one to encrypt a discrete logarithm instance under an Elgamal public key and prove to anyone that the correct value is encrypted.  

We use the elliptic curve implementation of [`arkworks`](https://github.com/arkworks-rs), and our implementation defaults to using the `secp256r1` curve, but is generic over the choice of curve and can easily be modified used to other curves implemented in `arkworks`.

Hashing is done with SHA512, using the Rust [`sha2`](https://docs.rs/sha2/latest/sha2/) crate. 

Our seed tree implementation is inspired by the one in the C implementation of the [LegRoast](https://github.com/WardBeullens/LegRoast) signature scheme. 

## Running Tests and Benchmarks
To run unit tests type `cargo test --release`. 

Sizes of the proofs and ciphertexts for the two schemes are computed in unit tests, use the script `run_size_benchmarks.sh` to run the tests and display the output. 

Benchmarks of the time required to run the main VE operations `Prove()`, `Verify()`, `Compress()` and `Recover()`
are also provided, and can be run with `cargo bench`.  To run only the DKGitH benchmarks, use 
```
cargo bench -- "^DKGitH"
```
and to run only the RDKGitH benchmarks use
```
cargo bench -- "^RDKGitH"
```

