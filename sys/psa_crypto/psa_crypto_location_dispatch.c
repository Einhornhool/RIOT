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

#include <stdio.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa_crypto_algorithm_dispatch.h"
#include "psa_crypto_slot_management.h"
#include "psa_crypto_se_management.h"
#include "psa_crypto_se_driver.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

psa_status_t psa_location_dispatch_generate_key(const psa_key_attributes_t *attributes,
                                                psa_key_slot_t * slot)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_generate == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->key_management->p_generate(drv_context, *((psa_key_slot_number_t*) slot->key.data), attributes, slot->key.pubkey_data, slot->key.pubkey_bytes, &slot->key.pubkey_bytes);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_generate_key(attributes, slot);
}

psa_status_t psa_location_dispatch_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            psa_key_slot_t * slot, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_import == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        *bits = 0;

        status = drv->key_management->p_import(drv_context, *((psa_key_slot_number_t*)slot->key.data), attributes, data, data_length, bits);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (*bits > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            return psa_builtin_import_key(attributes, data, data_length, slot->key.data, slot->key.bytes, &slot->key.bytes, bits);
        default:
            (void) status;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_location_dispatch_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const psa_key_slot_t * slot,
                                                    psa_algorithm_t alg)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);
    if (location != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        const psa_drv_se_t *drv;
        psa_drv_se_context_t *drv_context;
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

        if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
            if (drv->cipher == NULL || drv->cipher->p_setup == NULL) {
                return PSA_ERROR_NOT_SUPPORTED;
            }

            status = drv->cipher->p_setup(drv_context, &operation->ctx, *((psa_key_slot_number_t*) slot->key.data), attributes->policy.alg, PSA_CRYPTO_DRIVER_ENCRYPT);
            if (status != PSA_SUCCESS) {
                return status;
            }
            return PSA_SUCCESS;
        }
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */
    (void) operation;
    (void) attributes;
    (void) slot;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_location_dispatch_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const psa_key_slot_t * slot,
                                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) slot;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_location_dispatch_cipher_encrypt(  const psa_key_attributes_t * attributes,
                                                    psa_algorithm_t alg,
                                                    const psa_key_slot_t * slot,
                                                    const uint8_t * input,
                                                    size_t input_length,
                                                    uint8_t * output,
                                                    size_t output_size,
                                                    size_t * output_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (alg != PSA_ALG_ECB_NO_PADDING) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (drv->cipher == NULL || drv->cipher->p_ecb == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        status = drv->cipher->p_ecb(drv_context, *((psa_key_slot_number_t *) slot->key.data), alg, PSA_CRYPTO_DRIVER_ENCRYPT, input, input_length, output, output_size);
        if (status != PSA_SUCCESS) {
            return status;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_cipher_encrypt(attributes, alg, slot, input, input_length, output, output_size, output_length);
}

psa_status_t psa_location_dispatch_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const psa_key_slot_t * slot,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_sign == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return drv->asymmetric->p_sign(drv_context, *((psa_key_slot_number_t*)slot->key.data), alg, hash, hash_length, signature, signature_size, signature_length);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_sign_hash(attributes, alg, slot, hash, hash_length, signature, signature_size, signature_length);
}

psa_status_t psa_location_dispatch_verify_hash(const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const psa_key_slot_t * slot,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            const uint8_t * signature,
                                            size_t signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_verify == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return drv->asymmetric->p_verify(drv_context, *((psa_key_slot_number_t *)slot->key.data), alg, hash, hash_length, signature, signature_length);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_verify_hash(attributes, alg, slot, hash, hash_length, signature, signature_length);
}

psa_status_t psa_location_dispatch_mac_compute(const psa_key_attributes_t *attributes,
                                                psa_algorithm_t alg,
                                                const psa_key_slot_t * slot,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * mac,
                                                size_t mac_size,
                                                size_t * mac_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->mac == NULL || drv->mac->p_mac == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        DEBUG("Mac Compute SE\n");
        return drv->mac->p_mac(drv_context, input, input_length, *((psa_key_slot_number_t *) slot->key.data), alg, mac, mac_size, mac_length);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_mac_compute(attributes, alg, slot->key.data, slot->key.bytes, input, input_length, mac, mac_size, mac_length);
}

psa_status_t psa_location_dispatch_generate_random(uint8_t * output,
                                                size_t output_size)
{
    return psa_builtin_generate_random(output, output_size);
}
