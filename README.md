# Verifiable Encryption from MPC-in-the-Head
This repository contains implementations of verifiable encryption schemes
based on MPC-in-the-Head (MPCitH) proofs of knowledge. 

In general MPCitH allows you to create a proof of knowledge of $x$, such that $F(x) = y$. Our new construction allows you to simultaneously create a ciphertext encrypting $x$ with an arbitrary public key $pk$.  The proof guarantees that the ciphertext will decrypt correctly, and it can be verified without knowing the secret key associated to $pk$.  This is useful, for example, when exporting a key that is stored in hardware for backup.  The key must be encrypted with a public key $pk$ of a backup device, but the administrator requesting the backup does not know the secret key associated to $pk$.  By using verifiable encryption, the exporting device can prove that the exported key is the correct one, and that it will decrypt correctly on the backup device, should the first device fail.

Using our implementation you can 
* Encrypt an AES key to a Kyber (ML-KEM) public key, allowing you to back up AES keys verifiably and with post-quantum security (see the [helium_aes directory](https://github.com/akiratk0355/verenc-mpcith/tree/main/helium_aes))
* Encrypt an ECDSA private key to an Elgamal public key (using the [DKGitH implementation](https://github.com/akiratk0355/verenc-mpcith/tree/main/dkgith))

Details of our construction can be found in the accompanying paper:    
**Verifiable Encryption from MPC-in-the-Head**    
Akira Takahashi and Greg Zaverucha   
[IACR ePrint Report 2021/1704](https://eprint.iacr.org/2021/1704)

Acknowledgements for the code we build on are in the two subdirectories.  The code for the  [crypto-bigint](https://github.com/akiratk0355/verenc-mpcith/tree/main/crypto-bigint) package is not a dependency, we use it to compute some benchmarks to estimate the performance of another verfiable encryption scheme from the literature (that estimate can be found in [cs03-estimates.txt](https://github.com/akiratk0355/verenc-mpcith/tree/main/crypto-bigint/cs03-estimates.txt) ). 
