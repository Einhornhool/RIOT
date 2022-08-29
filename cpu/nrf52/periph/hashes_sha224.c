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
 * @brief       Glue code translating between PSA Crypto and the CryptoCell 310 driver APIs
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "kernel_defines.h"
#include "psa_periph_hashes_ctx.h"
#include "psa_periph_hashes_common.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

psa_status_t psa_hashes_sha224_setup(psa_hashes_sha224_ctx_t * ctx)
{
    DEBUG("Cryptocell SHA224 Setup\n");
    return common_hash_setup((CRYS_HASHUserContext_t *) ctx, CRYS_HASH_SHA224_mode);
}

psa_status_t psa_hashes_sha224_update(psa_hashes_sha224_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length)
{
    return common_hash_update((CRYS_HASHUserContext_t *) ctx, input, input_length);
}

psa_status_t psa_hashes_sha224_finish(psa_hashes_sha224_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    return common_hash_finish((CRYS_HASHUserContext_t *) ctx, hash, hash_size, hash_length);
}
