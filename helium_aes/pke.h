#ifndef PKE_H
#define PKE_H

#include <stdint.h>
#include <stddef.h>
#include "kyber-avx2/api.h"

/* pke.h: Defines a generic deterministic PKE interface and provides an implementation based on Kyber 512 */

#define PKE_SECRETKEYBYTES PQCLEAN_KYBER512_AVX2_CRYPTO_SECRETKEYBYTES
#define PKE_PUBLICKEYBYTES PQCLEAN_KYBER512_AVX2_CRYPTO_PUBLICKEYBYTES
#define PKE_CIPHERTEXTOVERHEADBYTES PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES 
#define PKE_RANDOMBYTES PQCLEAN_KYBER512_AVX2_RANDOMBYTES
#define PKE_ALGNAME PQCLEAN_KYBER512_AVX2_CRYPTO_ALGNAME

int pke_keygen(uint8_t* pk, uint8_t* sk);
int pke_encrypt(const uint8_t* pk, uint8_t* ctext, const uint8_t* rb, const uint8_t* msg, size_t msglen);
int pke_decrypt(const uint8_t* sk, const uint8_t* ctext, uint8_t* msg, size_t msglen);
#endif /* PKE_H */
