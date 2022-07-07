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
 * @brief       Structure definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include "crypto_types.h"
#include "crypto_sizes.h"
#include "crypto_contexts.h"

/**
 * @brief   This macro returns a suitable initializer for an AEAD operation object of type
 *          @ref psa_aead_operation_t.
 */
#define PSA_AEAD_OPERATION_INIT /* implementation-defined value */

/**
 * @brief   Return an initial value for an AEAD operation object.
 *
 * @return  psa_aead_operation_s
 */
psa_aead_operation_t psa_aead_operation_init(void);

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    psa_hash_context_t ctx;
};

/**
 * @brief   This macro returns a suitable initializer for a hash operation object of type
 *          @ref psa_hash_operation_t.
 */
#define PSA_HASH_OPERATION_INIT {0}

/**
 * @brief Return an initial value for a hash operation object.
 *
 * @return struct psa_hash_operation_s
 */
static inline struct psa_hash_operation_s psa_hash_operation_init(void)
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return v;
}

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
};
typedef struct psa_key_policy_s psa_key_policy_t;

struct psa_key_attributes_s
{
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    psa_key_id_t id;
    psa_key_policy_t policy;
};

/**
 * @brief   This macro returns a suitable initializer for a key attribute object of
 *          type @ref psa_key_attributes_t.
 */
#define PSA_KEY_ATTRIBUTES_INIT {0}

/**
 * @brief Return an initial value for a key attribute object.
 *
 * @return struct psa_key_attributes_s
 */
static inline struct psa_key_attributes_s psa_key_attributes_init(void)
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return v;
}

struct psa_cipher_operation_s
{
    uint8_t iv_required : 1;
    uint8_t iv_set : 1;
    uint8_t default_iv_length;
    psa_algorithm_t alg;
    union cipher_context {
        psa_cipher_context_t cipher_ctx;
#if IS_ACTIVE(CONFIG_PSA_SE_ATECCX08A)
        psa_se_cipher_context_t se_ctx;
#endif
    } backend_ctx;
};

/**
 * @brief This macro returns a suitable initializer for a cipher operation
 * object of type @ref psa_cipher_operation_t.
 */
#define PSA_CIPHER_OPERATION_INIT {0}

static inline struct psa_cipher_operation_s psa_cipher_operation_init(void)
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return v;
}

/**
 * @brief   This macro returns a suitable initializer for a key derivation operation object of
 *          type @ref psa_key_derivation_operation_t.
 */
#define PSA_KEY_DERIVATION_OPERATION_INIT /* implementation-defined value */

#endif /* PSA_CRYPTO_STRUCT_H */
