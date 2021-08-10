/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_cifra
 * @{
 *
 * @file
 * @brief
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#include <stdio.h>
#include "psa/crypto.h"
#include "aes.h"

#define AES_128_BLOCK_SIZE      (16)
#define AES_128_KEY_SIZE        (16)
#define AES_192_KEY_SIZE        (24)
#define AES_256_KEY_SIZE        (32)

#define ALG_IS_SUPPORTED(alg)   \
    (   (alg == PSA_ALG_ECB_NO_PADDING))

#define KEY_SIZE_IS_VALID(key_size) \
    (   (key_size == AES_128_KEY_SIZE) || \
        (key_size == AES_192_KEY_SIZE) || \
        (key_size == AES_256_KEY_SIZE))

psa_status_t psa_software_cipher_encrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{
    if (!ALG_IS_SUPPORTED(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!KEY_SIZE_IS_VALID(key_buffer_size)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_software_cipher_decrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{


    return PSA_SUCCESS;
}

psa_status_t psa_software_cipher_encrypt(psa_software_cipher_operation_t * operation,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{


    return PSA_SUCCESS;
}