#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch2/catch.hpp>

#include "../signature.h"

extern "C" {
  #include "../pke.h"
}

TEST_CASE("Param1: Prove, verify, compress, decrypt with benchmarks", "[ve]") {
  const char *message = "TestMessage";
  const signature_instance_t &instance = instance_get(AES128_L1_Param1);
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  keypair_t keypair;
  keypair.first = key;
  keypair.second = plaintext;
  keypair.second.insert(keypair.second.end(), ciphertext_expected.begin(),
                        ciphertext_expected.end());

  uint8_t ve_pk[PKE_PUBLICKEYBYTES];
  uint8_t ve_sk[PKE_SECRETKEYBYTES];
  int ret = pke_keygen(ve_pk, ve_sk);
  REQUIRE(ret == 0);

  std::vector<uint8_t> serialized_signature =
      helium_sign(instance, keypair, ve_pk, (const uint8_t *)message, strlen(message));
  std::cout << "signature length: " << serialized_signature.size()
            << " bytes\n";
  std::vector<uint8_t> ctext = helium_compress(instance, serialized_signature);
  std::cout << "VE ciphertext length: " << ctext.size() << " bytes\n";

  REQUIRE(helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                      (const uint8_t *)message, strlen(message)));

  std::vector<uint8_t> decrypted_key = helium_decrypt(instance, ve_sk, ctext);
  REQUIRE(decrypted_key.size() == 16);
  REQUIRE(decrypted_key == key);

  std::cout << "Benchmarks with N = " << instance.num_MPC_parties << " and tau = " << instance.num_repetitions << "\n";
  
  BENCHMARK("signing") {
    return helium_sign(instance, keypair, ve_pk, (const uint8_t *)message,
                       strlen(message));
  };
  BENCHMARK("verification") {
    return helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                         (const uint8_t *)message, strlen(message));
  };
  BENCHMARK("compress") {
    return helium_compress(instance, serialized_signature);
  };  

  BENCHMARK("decrypt") {
    return helium_decrypt(instance, ve_sk, ctext);
  };  
  

}

TEST_CASE("Param2: Prove, verify, compress, decrypt with benchmarks", "[ve]") {
  const char *message = "TestMessage";
  const signature_instance_t &instance = instance_get(AES128_L1_Param2);
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  keypair_t keypair;
  keypair.first = key;
  keypair.second = plaintext;
  keypair.second.insert(keypair.second.end(), ciphertext_expected.begin(),
                        ciphertext_expected.end());

  uint8_t ve_pk[PKE_PUBLICKEYBYTES];
  uint8_t ve_sk[PKE_SECRETKEYBYTES];
  int ret = pke_keygen(ve_pk, ve_sk);
  REQUIRE(ret == 0);

  std::vector<uint8_t> serialized_signature =
      helium_sign(instance, keypair, ve_pk, (const uint8_t *)message, strlen(message));
  std::cout << "signature length: " << serialized_signature.size()
            << " bytes\n";
  std::vector<uint8_t> ctext = helium_compress(instance, serialized_signature);
  std::cout << "VE ciphertext length: " << ctext.size() << " bytes\n";

  REQUIRE(helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                      (const uint8_t *)message, strlen(message)));

  std::vector<uint8_t> decrypted_key = helium_decrypt(instance, ve_sk, ctext);
  REQUIRE(decrypted_key.size() == 16);
  REQUIRE(decrypted_key == key);

  std::cout << "Benchmarks with N = " << instance.num_MPC_parties << " and tau = " << instance.num_repetitions << "\n";
  
  BENCHMARK("signing") {
    return helium_sign(instance, keypair, ve_pk, (const uint8_t *)message,
                       strlen(message));
  };
  BENCHMARK("verification") {
    return helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                         (const uint8_t *)message, strlen(message));
  };
  BENCHMARK("compress") {
    return helium_compress(instance, serialized_signature);
  };  

  BENCHMARK("decrypt") {
    return helium_decrypt(instance, ve_sk, ctext);
  };  
  
}

TEST_CASE("Param3: Prove, verify, compress, decrypt with benchmarks", "[ve]") {
  const char *message = "TestMessage";
  const signature_instance_t &instance = instance_get(AES128_L1_Param3);
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  keypair_t keypair;
  keypair.first = key;
  keypair.second = plaintext;
  keypair.second.insert(keypair.second.end(), ciphertext_expected.begin(),
                        ciphertext_expected.end());

  uint8_t ve_pk[PKE_PUBLICKEYBYTES];
  uint8_t ve_sk[PKE_SECRETKEYBYTES];
  int ret = pke_keygen(ve_pk, ve_sk);
  REQUIRE(ret == 0);

  std::vector<uint8_t> serialized_signature =
      helium_sign(instance, keypair, ve_pk, (const uint8_t *)message, strlen(message));
  std::cout << "signature length: " << serialized_signature.size()
            << " bytes\n";
  std::vector<uint8_t> ctext = helium_compress(instance, serialized_signature);
  std::cout << "VE ciphertext length: " << ctext.size() << " bytes\n";

  REQUIRE(helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                      (const uint8_t *)message, strlen(message)));

  std::vector<uint8_t> decrypted_key = helium_decrypt(instance, ve_sk, ctext);
  REQUIRE(decrypted_key.size() == 16);
  REQUIRE(decrypted_key == key);

  std::cout << "Benchmarks with N = " << instance.num_MPC_parties << " and tau = " << instance.num_repetitions << "\n";
  
  BENCHMARK("signing") {
    return helium_sign(instance, keypair, ve_pk, (const uint8_t *)message,
                       strlen(message));
  };
  BENCHMARK("verification") {
    return helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                         (const uint8_t *)message, strlen(message));
  };
  BENCHMARK("compress") {
    return helium_compress(instance, serialized_signature);
  };  

  BENCHMARK("decrypt") {
    return helium_decrypt(instance, ve_sk, ctext);
  };  
  
}

void print_hex(const char* s, const uint8_t* data, size_t len) 
{
    printf("%s: ", s);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }    
    printf("\n");
}

TEST_CASE("Prove verify compress decrypt many times", "[ve]") {

  for(uint16_t i = 0; i < 100; i++) {   
  uint8_t message[2] = {0x00, 0x00};
  message[0] = ((uint8_t*)&i)[0];
  message[1] = ((uint8_t*)&i)[1];  

  const signature_instance_t &instance = instance_get(AES128_L1_Param3);
  const std::vector<uint8_t> key = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                    0xff, 0xff, 0xff, 0xff};
  const std::vector<uint8_t> plaintext = {0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00};
  const std::vector<uint8_t> ciphertext_expected = {
      0x0b, 0x5a, 0x81, 0x4d, 0x95, 0x60, 0x1c, 0xc7,
      0xef, 0xe7, 0x12, 0x28, 0x3e, 0x05, 0xef, 0x8f};

  keypair_t keypair;
  keypair.first = key;
  keypair.second = plaintext;
  keypair.second.insert(keypair.second.end(), ciphertext_expected.begin(), ciphertext_expected.end());

  uint8_t ve_pk[PKE_PUBLICKEYBYTES];
  uint8_t ve_sk[PKE_SECRETKEYBYTES];
  int ret = pke_keygen(ve_pk, ve_sk);
  REQUIRE(ret == 0);

  std::vector<uint8_t> serialized_signature =
      helium_sign(instance, keypair, ve_pk, message, sizeof(message));

  std::vector<uint8_t> ctext = helium_compress(instance, serialized_signature);

  REQUIRE(helium_verify(instance, keypair.second, serialized_signature, ve_pk,
                      message, sizeof(message)));

  std::vector<uint8_t> decrypted_key = helium_decrypt(instance, ve_sk, ctext);
  REQUIRE(decrypted_key.size() == 16);
  REQUIRE(decrypted_key == key);

  }

}
