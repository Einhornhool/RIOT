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
 * @brief       Context definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 */

#ifndef PSA_CRYPTO_CONTEXTS_H
#define PSA_CRYPTO_CONTEXTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"

#include "psa/crypto_includes.h"

/**
 * @brief   Structure containing the hash contexts needed by the application.
 */
typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if IS_ACTIVE(CONFIG_HASHES_MD5)
    psa_hashes_md5_ctx_t md5;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA1)
    psa_hashes_sha1_ctx_t sha1;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA224)
    psa_hashes_sha224_ctx_t sha224;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA256)
    psa_hashes_sha256_ctx_t sha256;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA512)
    psa_hashes_sha512_ctx_t sha512;
#endif
} psa_hash_context_t;

/**
 * @brief   Structure containing the cipher contexts needed by the application.
 */
typedef union {
    unsigned dummy;
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_128)
    psa_cipher_aes_128_ctx_t aes_128;
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_192)
    psa_cipher_aes_192_ctx_t aes_192;
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_256)
    psa_cipher_aes_256_ctx_t aes_256;
#endif
} psa_cipher_context_t;

/**
 * @brief   Structure containing the secure element specific cipher contexts needed by the
 *          application.
 */
typedef struct {
    psa_encrypt_or_decrypt_t direction;
    union driver_context {
        unsigned dummy;
    #if IS_ACTIVE(CONFIG_PSA_SE_ATECCX08A)
        atca_aes_cbc_ctx_t atca_aes_cbc;
    #endif
    } drv_ctx;
} psa_se_cipher_context_t;

#ifdef __cplusplus
}
#endif

#endif /* PSA_CRYPTO_CONTEXTS_H */
/** @} */
