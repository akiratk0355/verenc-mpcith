/*
 *  This file is part of the optimized implementation of the Picnic signature
 * scheme. See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#include "instances.h"

#include <stdexcept>


/* key_size, block_size, num_blocks, num_sboxes */
constexpr aes_params_t AES128 = {16, 16, 200};

static const signature_instance_t instances[PARAMETER_SET_MAX_INDEX] = {
    {
        {0, 0, 0},
        0,
        0,
        0,
        0,
        0,
        0,
        PARAMETER_SET_INVALID,
    },
    /* some sample instances for 16, 57 and 256 */
    /* AES params, digest size, seed size, T, N, commitment size, L */
    {AES128, 32, 16, 31, 16, COMMITMENT_SIZE, 200, AES128_L1_Param1},
    {AES128, 32, 16, 22, 57, COMMITMENT_SIZE, 200, AES128_L1_Param2},
    {AES128, 32, 16, 16, 256, COMMITMENT_SIZE, 200, AES128_L1_Param3},

};

const signature_instance_t &instance_get(params_t param) {
  if (param <= PARAMETER_SET_INVALID || param >= PARAMETER_SET_MAX_INDEX) {
    throw std::runtime_error("invalid parameter set");
  }

  return instances[param];
}
