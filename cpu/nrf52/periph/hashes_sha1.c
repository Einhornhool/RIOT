/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto cpu_nrf52
 * @{
 *
 * @file
 * @brief       Glue code for ARM Cryptocell driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/hashes_sha1.h"
#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hash_error.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define CC310_MAX_HASH_INPUT_BLOCK       (0xFFF0)

static psa_status_t cc310_to_psa_error(CRYSError_t error)
{
    switch(error) {
        case CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR:
        case CRYS_HASH_IS_NOT_SUPPORTED:
            return PSA_ERROR_NOT_SUPPORTED;
        case CRYS_HASH_USER_CONTEXT_CORRUPTED_ERROR:
            return PSA_ERROR_CORRUPTION_DETECTED;
        case CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR:
        case CRYS_HASH_DATA_SIZE_ILLEGAL:
            return PSA_ERROR_DATA_INVALID;
        case CRYS_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR:
        case CRYS_HASH_ILLEGAL_PARAMS_ERROR:
        case CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR:
        case CRYS_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR:
        case CRYS_HASH_CTX_SIZES_ERROR:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

psa_status_t psa_hashes_sha1_setup(psa_hashes_sha1_operation_t * operation,
                                           psa_algorithm_t alg)
{
    DEBUG("Cryptocell Setup\n");
    int ret = CRYS_HASH_Init(operation, CRYS_HASH_SHA1_mode);

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }

    (void) alg;
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha1_update(psa_hashes_sha1_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;
    do {
        if (input_length > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            input_length -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = input_length;
            input_length = 0;
        }

        cryptocell_enable();
        ret = CRYS_HASH_Update(operation, (uint8_t*)(input + offset), size);
        cryptocell_disable();

        offset += size;
    } while ((input_length > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha1_finish(psa_hashes_sha1_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    int ret = 0;
    cryptocell_enable();
    ret = CRYS_HASH_Finish(operation, (uint32_t*)hash);
    cryptocell_disable();

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}