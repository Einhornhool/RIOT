/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Meta API for RIOT software hashes for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#include "kernel_defines.h"

#if !IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA1)
#include "psa/crypto.h"

psa_status_t psa_hashes_sha1_setup(psa_hashes_sha1_operation_t * operation,
                                           psa_algorithm_t alg)
{
    sha1_init(operation);

    (void) alg;
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha1_update(psa_hashes_sha1_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    sha1_update(operation, input, input_length);
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha1_finish(psa_hashes_sha1_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    sha1_final(operation, hash);

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}
#endif
