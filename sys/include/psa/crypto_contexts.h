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
 * @brief       Context definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#if IS_ACTIVE(CONFIG_HASHES_SHA1)
#include "hashes_sha1.h"
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA256)
#include "hashes_sha256.h"
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hashes.h"
#endif

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if IS_ACTIVE(CONFIG_HASHES_SHA1)
    psa_hashes_sha1_operation_t sha1;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA256)
    psa_hashes_sha256_operation_t sha256;
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
    psa_hash_atca_operation_t atca_ctx;
#endif
} psa_hash_context_t;

#endif /* CRYPTO_CONTEXT_H */
