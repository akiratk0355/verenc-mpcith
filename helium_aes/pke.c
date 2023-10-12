#include "pke.h"
#include "macros.h"

#include "kdf.h"
#include "kyber-avx2/api.h"
#include <stdio.h>


void print_hex(const char* s, const uint8_t* data, size_t len) 
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }    
    printf("\n");
}

/* Generate a key pair; returns 0 on success, nonzero on failure.  
  The input buffers must have size PKE_PUBLICKEYBYTES and PKE_SECRETKEYBYTES respectively */
int pke_keygen(uint8_t* pk, uint8_t* sk) {


  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
  if(ret) {
    printf("kyber key gen failed\n");
  }

  return ret;

}

int pke_encrypt(const uint8_t* pk, uint8_t* ctext, const uint8_t* rb, const uint8_t* msg, size_t msglen) {

  uint8_t shared_secret[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};  

  if(msglen > PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES) {
    printf("%s: msg len too large\n", __func__);
    return -1;
  }

  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_enc_determinisitic(ctext, shared_secret, pk, rb);
  if(ret) {
    printf("kyber enc failed\n");
    return -1;
  }

//  print_hex("encrypt shared secret", shared_secret, sizeof(shared_secret));

  uint8_t* encrypted_msg = &ctext[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES];
  for(size_t i = 0; i < msglen; i++) {
    encrypted_msg[i] = msg[i] ^ shared_secret[i];
  }

  return ret;
}

int pke_decrypt(const uint8_t* sk, const uint8_t* ctext, uint8_t* msg, size_t msglen) {

  uint8_t shared_secret[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};  

  if(msglen > PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES) {
    printf("msg len too large\n");
    return -1;
  }

  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_dec_with_error(shared_secret, ctext, sk);
  if(ret) {
    printf("kyber dec failed\n");
    return -1;
  }
 // print_hex("decrypt shared secret", shared_secret, sizeof(shared_secret));

  const uint8_t* encrypted_msg = &ctext[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES];
  for(size_t i = 0; i < msglen; i++) {
    msg[i] = encrypted_msg[i] ^ shared_secret[i];
  }

  return ret;
}



