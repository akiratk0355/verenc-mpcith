#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "../aes.h"

TEST_CASE("AES-128 KAT", "[aes]") {
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  std::vector<uint8_t> ct;

  REQUIRE(AES128::aes_128(key, plaintext, ct) == true);
  REQUIRE(ct == ciphertext_expected);
}

TEST_CASE("AES-192 KAT", "[aes]") {
  const std::vector<uint8_t> key = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  std::vector<uint8_t> plaintext = {0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
  plaintext.insert(plaintext.end(), plaintext.begin(),
                   plaintext.begin() + plaintext.size());
  std::vector<uint8_t> ciphertext_expected = {
      0x15, 0xc5, 0x99, 0x50, 0xf7, 0x9f, 0x74, 0x21,
      0x4b, 0xc8, 0xfc, 0x50, 0x7c, 0x5f, 0x9b, 0xa6};
  ciphertext_expected.insert(
      ciphertext_expected.end(), ciphertext_expected.begin(),
      ciphertext_expected.begin() + ciphertext_expected.size());

  std::vector<uint8_t> ct;

  REQUIRE(AES192::aes_192(key, plaintext, ct) == true);
  REQUIRE(ct == ciphertext_expected);
}

TEST_CASE("AES-256 KAT", "[aes]") {
  const std::vector<uint8_t> key = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
  plaintext.insert(plaintext.end(), plaintext.begin(),
                   plaintext.begin() + plaintext.size());

  std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5c, 0xe5, 0x2a, 0x5c, 0xfc, 0x30, 0x02,
      0x19, 0x22, 0x26, 0x92, 0x07, 0xb7, 0xd9, 0x66};
  ciphertext_expected.insert(
      ciphertext_expected.end(), ciphertext_expected.begin(),
      ciphertext_expected.begin() + ciphertext_expected.size());

  std::vector<uint8_t> ct;

  REQUIRE(AES256::aes_256(key, plaintext, ct) == true);
  REQUIRE(ct == ciphertext_expected);
}

TEST_CASE("AES-128 normal is equal to sbox-saving", "[aes]") {
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  std::vector<uint8_t> ct;
  std::vector<uint8_t> ct2;

  REQUIRE(AES128::aes_128(key, plaintext, ct) == true);
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> sbox_states =
      AES128::aes_128_with_sbox_output(key, plaintext, ct2);
  REQUIRE(ct == ciphertext_expected);
  REQUIRE(ct == ct2);
  REQUIRE(sbox_states.first.size() == AES128::NUM_SBOXES);
  REQUIRE(sbox_states.second.size() == AES128::NUM_SBOXES);
}

TEST_CASE("AES-192 normal is equal to sbox-saving", "[aes]") {
  const std::vector<uint8_t> key = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  std::vector<uint8_t> plaintext = {0x02, 0x02, 0x02, 0x02, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
  plaintext.insert(plaintext.end(), plaintext.begin(),
                   plaintext.begin() + plaintext.size());
  std::vector<uint8_t> ciphertext_expected = {
      0x15, 0xc5, 0x99, 0x50, 0xf7, 0x9f, 0x74, 0x21,
      0x4b, 0xc8, 0xfc, 0x50, 0x7c, 0x5f, 0x9b, 0xa6};
  ciphertext_expected.insert(
      ciphertext_expected.end(), ciphertext_expected.begin(),
      ciphertext_expected.begin() + ciphertext_expected.size());

  std::vector<uint8_t> ct;
  std::vector<uint8_t> ct2;

  REQUIRE(AES192::aes_192(key, plaintext, ct) == true);
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> sbox_states =
      AES192::aes_192_with_sbox_output(key, plaintext, ct2);
  REQUIRE(ct == ciphertext_expected);
  REQUIRE(ct == ct2);
  REQUIRE(sbox_states.first.size() == AES192::NUM_SBOXES);
  REQUIRE(sbox_states.second.size() == AES192::NUM_SBOXES);
}

TEST_CASE("AES-256 normal is equal to sbox-saving", "[aes]") {
  const std::vector<uint8_t> key = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
  plaintext.insert(plaintext.end(), plaintext.begin(),
                   plaintext.begin() + plaintext.size());
  std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5c, 0xe5, 0x2a, 0x5c, 0xfc, 0x30, 0x02,
      0x19, 0x22, 0x26, 0x92, 0x07, 0xb7, 0xd9, 0x66};
  ciphertext_expected.insert(
      ciphertext_expected.end(), ciphertext_expected.begin(),
      ciphertext_expected.begin() + ciphertext_expected.size());

  std::vector<uint8_t> ct;
  std::vector<uint8_t> ct2;

  REQUIRE(AES256::aes_256(key, plaintext, ct) == true);
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> sbox_states =
      AES256::aes_256_with_sbox_output(key, plaintext, ct2);
  REQUIRE(ct == ciphertext_expected);
  REQUIRE(ct == ct2);
  REQUIRE(sbox_states.first.size() == AES256::NUM_SBOXES);
  REQUIRE(sbox_states.second.size() == AES256::NUM_SBOXES);
}