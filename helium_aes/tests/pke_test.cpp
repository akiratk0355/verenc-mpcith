#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

extern "C" {
#include "../pke.h"
#include <stdlib.h>
#include "../kyber-avx2/api.h"
}

void print_hex(const char* s, const uint8_t* data, size_t len) 
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }    
    printf("\n");
}

TEST_CASE("Kyber round-trip", "[pke]") {
  uint8_t pk[PQCLEAN_KYBER512_AVX2_CRYPTO_PUBLICKEYBYTES] = {0};
  uint8_t sk[PQCLEAN_KYBER512_AVX2_CRYPTO_SECRETKEYBYTES] = {0};
  uint8_t ctext[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES] = {0};
  uint8_t ss[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};
  uint8_t ss2[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};

  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
  REQUIRE(ret == 0);

  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_enc(ctext, ss, pk);
  REQUIRE(ret == 0);

  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_dec(ss2, ctext, sk);
  REQUIRE(ret == 0);

  // print_hex("enc ss", ss, sizeof(ss));
  // print_hex("dec ss", ss2, sizeof(ss2));
  REQUIRE(memcmp(ss, ss2, sizeof(ss)) == 0);
}

TEST_CASE("Kyber det round-trip", "[pke]") {
  uint8_t pk[PQCLEAN_KYBER512_AVX2_CRYPTO_PUBLICKEYBYTES] = {0};
  uint8_t sk[PQCLEAN_KYBER512_AVX2_CRYPTO_SECRETKEYBYTES] = {0};
  uint8_t ctext[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES] = {0};
  uint8_t ctext2[PQCLEAN_KYBER512_AVX2_CRYPTO_CIPHERTEXTBYTES] = {0};
  uint8_t ss[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};
  uint8_t ss2[PQCLEAN_KYBER512_AVX2_CRYPTO_BYTES] = {0};
  uint8_t rb[PQCLEAN_KYBER512_AVX2_RANDOMBYTES] = {0};

  memset(rb, 0x07, sizeof(rb));

  int ret = PQCLEAN_KYBER512_AVX2_crypto_kem_keypair(pk, sk);
  REQUIRE(ret == 0);

  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_enc_determinisitic(ctext, ss, pk, rb);
  REQUIRE(ret == 0);

  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_dec(ss2, ctext, sk);
  REQUIRE(ret == 0);

  // print_hex("enc ss", ss, sizeof(ss));
  // print_hex("dec ss", ss2, sizeof(ss2));
  REQUIRE(memcmp(ss, ss2, sizeof(ss)) == 0);

  // re-encrypt with same random bytes; expect same ciphertext
  ret = PQCLEAN_KYBER512_AVX2_crypto_kem_enc_determinisitic(ctext2, ss, pk, rb);
  REQUIRE(ret == 0);  
  REQUIRE(memcmp(ctext, ctext2, sizeof(ctext)) == 0);
}

TEST_CASE("PKE key generation", "[pke]") {

  uint8_t pk[PKE_PUBLICKEYBYTES] = {0};
  uint8_t sk[PKE_SECRETKEYBYTES] = {0};

  int ret = pke_keygen(pk, sk);

  REQUIRE(ret == 0);
}

TEST_CASE("PKE round-trip", "[pke]") {

  const size_t MSG_LEN = 16;
  uint8_t pk[PKE_PUBLICKEYBYTES] = {0};
  uint8_t sk[PKE_SECRETKEYBYTES] = {0};
  uint8_t msg[MSG_LEN] = {0};
  uint8_t msg2[MSG_LEN] = {0};
  uint8_t ctext[PKE_CIPHERTEXTOVERHEADBYTES + MSG_LEN] = {0};
  uint8_t ctext2[PKE_CIPHERTEXTOVERHEADBYTES + MSG_LEN] = {0};
  uint8_t ctext3[PKE_CIPHERTEXTOVERHEADBYTES + MSG_LEN] = {0};
  uint8_t rb[PKE_RANDOMBYTES] = {0};
  uint8_t rb2[PKE_RANDOMBYTES] = {0};

  memset(rb, 0x07, sizeof(rb));
  memset(rb2, 0x08, sizeof(rb2));
  int ret = pke_keygen(pk, sk);
  REQUIRE(ret == 0);
  ret = pke_encrypt(pk, ctext, rb, msg, MSG_LEN);
  REQUIRE(ret == 0);
  ret = pke_encrypt(pk, ctext2, rb, msg, MSG_LEN);
  REQUIRE(ret == 0);  
  ret = pke_encrypt(pk, ctext3, rb2, msg, MSG_LEN);
  REQUIRE(ret == 0);    
  ret = pke_decrypt(sk, ctext, msg2, MSG_LEN);
  REQUIRE(ret == 0);
  // print_hex("msg ", msg, MSG_LEN);
  // print_hex("msg2", msg2, MSG_LEN);
  REQUIRE(memcmp(msg, msg2, MSG_LEN) == 0);   // Is decryption correct?
  REQUIRE(memcmp(ctext, ctext2, sizeof(ctext)) == 0); // Is encryption deterministic?
  REQUIRE(memcmp(ctext, ctext3, sizeof(ctext)) != 0); // Does encryption depend on rb input?
}
