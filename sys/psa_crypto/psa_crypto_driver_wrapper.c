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
#include "include/psa_hashes.h"
#include "include/psa_ciphers.h"
#include "include/psa_crypto_slot_management.h"
#include "include/psa_builtin_key_management.h"
#include "include/psa_crypto_se_management.h"
#include "include/psa_crypto_se_driver.h"

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    switch(alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            status = psa_hashes_md5_setup(&operation->ctx.md5);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            status = psa_hashes_sha1_setup(&operation->ctx.sha1);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            status = psa_hashes_sha224_setup(&operation->ctx.sha224);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            status = psa_hashes_sha256_setup(&operation->ctx.sha256);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
        default:
            (void) status;
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            return psa_hashes_md5_update(&operation->ctx.md5, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            return psa_hashes_sha1_update(&operation->ctx.sha1, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            return psa_hashes_sha224_update(&operation->ctx.sha224, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            return psa_hashes_sha256_update(&operation->ctx.sha256, input, input_length);
    #endif
        default:
            (void) operation;
            (void) input;
            (void) input_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            return psa_hashes_md5_finish(&operation->ctx.md5, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            return psa_hashes_sha1_finish(&operation->ctx.sha1, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            return psa_hashes_sha224_finish(&operation->ctx.sha224, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            return psa_hashes_sha256_finish(&operation->ctx.sha256, hash, hash_size, hash_length);
    #endif
        default:
            (void) operation;
            (void) hash;
            (void) hash_size;
            (void) hash_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_export_public_key(  const psa_key_attributes_t *attributes,
                                                    uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    uint8_t * data,
                                                    size_t data_size,
                                                    size_t * data_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_export_public == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->key_management->p_export_public(drv_context, *((psa_key_slot_number_t*)key_buffer), data, data_size, data_length);
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_generate_key(   const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_generate == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        size_t pubkey_length = 0;
        return drv->key_management->p_generate(drv_context, *((psa_key_slot_number_t*)key_buffer), attributes, NULL, 0, &pubkey_length);
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) key_buffer_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_import == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        *bits = PSA_MAX_KEY_BITS + 1;
        status = drv->key_management->p_import(drv_context, *((psa_key_slot_number_t*)key_buffer), attributes, data, data_length, bits);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (*bits > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            return psa_builtin_import_key(attributes, data, data_length, key_buffer, key_buffer_size, key_buffer_length, bits);
        default:
            (void) status;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    psa_algorithm_t alg)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);
    if (location != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        const psa_drv_se_t *drv;
        psa_drv_se_context_t *drv_context;
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

        if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
            if (drv->cipher == NULL || drv->cipher->p_setup == NULL) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            status = drv->cipher->p_setup(drv_context, &operation->ctx, *((psa_key_slot_number_t*) key_buffer), attributes->policy.alg, PSA_CRYPTO_DRIVER_ENCRYPT);
            if (status != PSA_SUCCESS) {
                return status;
            }
            return PSA_SUCCESS;
        }
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

#if IS_ACTIVE(CONFIG_CIPHER_AES_128)
static psa_status_t psa_cipher_cbc_encrypt( psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    psa_key_attributes_t attributes = slot->attr;

    switch(attributes.type) {
        case PSA_KEY_TYPE_AES:
            return psa_cipher_aes_cbc_encrypt(&attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
        default:
            (void) slot;
            (void) input;
            (void) input_length;
            (void) output;
            (void) output_size;
            (void) output_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}
#endif

psa_status_t psa_driver_wrapper_cipher_encrypt( psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
        const psa_drv_se_t *drv;
        psa_drv_se_context_t *drv_context;

        if (alg != PSA_ALG_ECB_NO_PADDING) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        if (psa_get_se_driver(slot->attr.lifetime, &drv, &drv_context)) {
            if (drv->cipher == NULL || drv->cipher->p_ecb == NULL) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            status = drv->cipher->p_ecb(drv_context, *((psa_key_slot_number_t *) slot->key.data), alg, PSA_CRYPTO_DRIVER_ENCRYPT, input, input_length, output, output_size);
            if (status != PSA_SUCCESS) {
                return status;
            }
            return PSA_SUCCESS;
        }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    switch(alg) {
#if IS_ACTIVE(CONFIG_CIPHER_AES_128)
        case PSA_ALG_CBC_NO_PADDING:
            return psa_cipher_cbc_encrypt(slot, alg, input, input_length, output, output_size, output_length);
#endif
        default:
        (void) slot;
        (void) input;
        (void) input_length;
        (void) output;
        (void) output_size;
        (void) output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_driver_wrapper_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * data,
                                            size_t data_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_sign == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->asymmetric->p_sign(drv_context, *((psa_key_slot_number_t*)key_buffer), alg, data, data_length, signature, signature_size, signature_length);
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) data;
    (void) data_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_verify_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * data,
                                            size_t data_length,
                                            const uint8_t * signature,
                                            size_t signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_verify == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->asymmetric->p_verify(drv_context, *((psa_key_slot_number_t*)key_buffer), alg, data, data_length, signature, signature_length);
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) data;
    (void) data_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}