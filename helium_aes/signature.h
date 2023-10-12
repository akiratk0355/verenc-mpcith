#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <vector>

#include "instances.h"
#include "types.h"

// crypto api
keypair_t helium_keygen(const signature_instance_t &instance);

// The verifiable encryption Prove function; outputs the proof (which contains a ciphertext).
std::vector<uint8_t> helium_sign(const signature_instance_t &instance,
                                const keypair_t &keypair,
                                const uint8_t* ve_pk,
                                const uint8_t *message, size_t message_len);

// The verifiable encryption Verify function; verifies a proof.
bool helium_verify(const signature_instance_t &instance,
                  const std::vector<uint8_t> &pk,
                  const std::vector<uint8_t> &signature, 
                  const uint8_t* ve_pk, 
                  const uint8_t *message, size_t message_len);

// Separates the verifiable encryption ciphertext from the proof
std::vector<uint8_t> helium_compress(const signature_instance_t &instance, const std::vector<uint8_t> &signature_bytes);

// Decrypts the verifiable encryption ciphertext
std::vector<uint8_t> helium_decrypt(const signature_instance_t &instance, const uint8_t* ve_sk, std::vector<uint8_t> &ve_ciphertext); 