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
 * @brief       Wrapper to combine several available cryptographic backends.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "kernel_defines.h"
#include "psa/crypto.h"

#if IS_ACTIVE(CONFIG_HASHES_SHA1)
#include "psa/hashes_sha1.h"
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA256)
#include "psa/hashes_sha256.h"
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hashes.h"
#endif

#define PSA_CRYPTO_TRANSPARENT_DRIVER_ID    (1)
#if IS_ACTIVE(CONFIG_SE_HASHES)
#define PSA_CRYPTO_SE_DRIVER_ID         (2)
#endif

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    switch(alg) {
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            status = psa_hashes_sha1_setup(&operation->ctx.sha1, alg);
            if (status == PSA_SUCCESS) {
                operation->driver_id = PSA_CRYPTO_TRANSPARENT_DRIVER_ID;
            }
            if (status != PSA_ERROR_NOT_SUPPORTED) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            status = psa_hashes_sha256_setup(&operation->ctx.sha256, alg);
            if (status == PSA_SUCCESS) {
                operation->driver_id = PSA_CRYPTO_TRANSPARENT_DRIVER_ID;
            }
            if (status != PSA_ERROR_NOT_SUPPORTED) {
                return status;
            }
            break;
    #endif
    }

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
    status = atca_hash_setup(&(operation->ctx.atca_ctx), alg);
    if (status == PSA_SUCCESS) {
        operation->driver_id = PSA_CRYPTO_SE_DRIVER_ID;
    }
    if (status != PSA_ERROR_NOT_SUPPORTED) {
        return status;
    }
    #endif

    (void) status;
    (void) operation;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if (operation->driver_id == PSA_CRYPTO_TRANSPARENT_DRIVER_ID) {
        switch(operation->alg) {
        #if IS_ACTIVE(CONFIG_HASHES_SHA1)
            case PSA_ALG_SHA_1:
                return psa_hashes_sha1_update(&(operation->ctx.sha1), input, input_length);
        #endif
        #if IS_ACTIVE(CONFIG_HASHES_SHA256)
            case PSA_ALG_SHA_256:
                return psa_hashes_sha256_update(&(operation->ctx.sha256), input, input_length);
        #endif
        }
    }
#if IS_ACTIVE(CONFIG_SE_HASHES)
    else if (operation->driver_id == PSA_CRYPTO_SE_DRIVER_ID){
    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
        return atca_hash_update(&(operation->ctx.atca_ctx), input, input_length);
    #endif
    }
#endif
    (void) input;
    (void) input_length;
    return PSA_ERROR_BAD_STATE;
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    if (operation->driver_id == PSA_CRYPTO_TRANSPARENT_DRIVER_ID) {
        switch(operation->alg) {
            #if IS_ACTIVE(CONFIG_HASHES_SHA1)
                case PSA_ALG_SHA_1:
                    return psa_hashes_sha1_finish(&(operation->ctx.sha1), hash, hash_size, hash_length);
                    break;
            #endif
            #if IS_ACTIVE(CONFIG_HASHES_SHA256)
                case PSA_ALG_SHA_256:
                    return psa_hashes_sha256_finish(&(operation->ctx.sha256), hash, hash_size, hash_length);
                    break;
            #endif
        }
    }
#if IS_ACTIVE(CONFIG_SE_HASHES)
    else if (operation->driver_id == PSA_CRYPTO_SE_DRIVER_ID) {
    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
        return atca_hash_finish(&(operation->ctx.atca_ctx), hash, hash_size, hash_length);
    #endif
    }
#endif
    (void) hash;
    (void) hash_size;
    (void) hash_length;
    return PSA_ERROR_BAD_STATE;
}
