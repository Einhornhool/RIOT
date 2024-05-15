/*
 * Copyright (c) 2020, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file This file collects the alternative functions to replace the
 *       implementations in mbed-crypto if the corresponding mbed-crypto
 *       MBEDTLS__FUNCTION_NAME__ALT is selected.
 *
 * \note This applies only when the legacy driver API based on the _ALT
 *       implementations is selected, and has no effect when the PSA driver
 *       interface is used. This is going to be deprecated in a future version
 *       of mbed TLS.
 */

#include "mbedtls/aes.h"
#include "mbedtls/error.h"

#pragma message("mbedtls_internal_aes_decrypt() is replaced by an empty wrapper to decrease memory footprint")
/*
 * Replace the decryption process with an empty wrapper in AES-CCM mode.
 * The decryption process is exactly the same as encryption process. Skip
 * the decryption implementation to decrease memory footprint.
 */
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16])
{
    (void)ctx;
    (void)input;
    (void)output;

    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}

#pragma message("mbedtls_aes_setkey_dec() is replaced by an empty wrapper to decrease memory footprint")
/*
 * Replace the decryption process with an empty wrapper in AES-CCM mode.
 * The decryption process is exactly the same as encryption process. Skip
 * the decryption key setting to decrease memory footprint.
 */
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits)
{
    (void)ctx;
    (void)key;
    (void)keybits;

    return MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED;
}
