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
 * @brief       Function and type declarations for built-in software hashes for
 *              PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_BUILTIN_HASHES_SHA256_H
#define PSA_BUILTIN_HASHES_SHA256_H

#include "kernel_defines.h"
#include "crypto.h"

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA256)
#include "periph_hashes_context.h"
#else
#include "hashes/sha256.h"
typedef sha256_context_t psa_hashes_sha256_operation_t;
#endif

psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* PSA_BUILTIN_HASHES_H */
