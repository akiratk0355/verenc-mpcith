#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

void print_hex(const char* s, const uint8_t* data, size_t len) 
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }    
    printf("\n");
}

int main() {

  uint8_t pk[PQCLEAN_KYBER512_AVX2_CRYPTO_PUBLICKEYBYTES] = {0};
  uint8_t sk[PQCLEAN_KYBER512_AVX2_CRYPTO_SECRETKEYBYTES] = {0};
  uint8_t ctext[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES] = {0};
  uint8_t ss[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};
  uint8_t ss2[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};

  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
  if(ret) {
      printf("Keygen failed\n");
  }


  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_enc(ctext, ss, pk);
  if(ret) {
      printf("Failed to encrypt\n");
  }

  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_dec(ss2, ctext, sk);
  if(ret) {
      printf("Failed to decrypt\n");
  }

  print_hex("enc ss", ss, sizeof(ss));
  print_hex("dec ss", ss2, sizeof(ss2));
  if(memcmp(ss, ss2, sizeof(ss)) != 0) {
      printf("Failed\n");
      return -1;
  }
  printf("success\n");
  return 0;

}
