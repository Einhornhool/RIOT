/*
 * Copyright (C) 2022 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @brief       Glue code translating between PSA Crypto and the mbedTLS legacy API
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "psa/crypto.h"
#include "mbedtls_psa_error.h"
#include "mbedtls/sha256.h"
#include "mbedtls/platform_util.h"

psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_ctx_t *ctx)
{
    mbedtls_sha256_init((mbedtls_sha256_context *)ctx);
    return mbedtls_sha256_starts_ret((mbedtls_sha256_context *)ctx, 0 );
}

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_ctx_t *ctx,
                                      const uint8_t *input,
                                      size_t input_length)
{
    int ret = mbedtls_sha256_update_ret((mbedtls_sha256_context *)ctx, input, input_length);
    if (ret != 0) {
        return mbedtls_to_psa_error( ret );
    }
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_ctx_t *ctx,
                                      uint8_t *hash,
                                      size_t hash_size,
                                      size_t *hash_length)
{
    int ret = ret = mbedtls_sha256_finish_ret( (mbedtls_sha256_context *)ctx, hash );

    if (ret != 0) {
        return mbedtls_to_psa_error( ret );
    }

    (void)hash_size;
    (void)hash_length;
    return PSA_SUCCESS;
}
