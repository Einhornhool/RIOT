/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_driver_cryptocell
 * @{
 *
 * @brief       Glue code translating between PSA Crypto and the CryptoCell 310 driver APIs
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "psa/crypto.h"
#include "vendor/nrf52840.h"
#include "ssi_aes.h"
#include "sns_silib.h"
#include "psa_error.h"
#include "cryptocell_util.h"

#define ENABLE_DEBUG    0
#include "debug.h"

#define CC310_MAX_AES_INPUT_BLOCK       (0xFFF0)

psa_status_t common_aes_setup(SaSiAesUserContext_t *ctx,
                              SaSiAesEncryptMode_t direction,
                              SaSiAesOperationMode_t mode,
                              SaSiAesPaddingType_t padding,
                              const uint8_t *iv,
                              const uint8_t *key_buffer,
                              size_t key_buffer_size)
{
    SaSiAesUserKeyData_t key;

    int ret = SaSi_AesInit(ctx, direction, mode, padding);

    if (ret != SASI_OK) {
        DEBUG("AES Setup SaSi Error: %x\n", ret);
        return SaSi_to_psa_error(ret);
    }
    key.keySize = key_buffer_size;
    key.pKey = (uint8_t *)key_buffer;

    ret = SaSi_AesSetKey(ctx, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SASI_OK) {
        DEBUG("AES Setup SaSi Error: %x\n", ret);
        return SaSi_to_psa_error(ret);
    }

    ret = SaSi_AesSetIv(ctx, iv);
    if (ret != SASI_OK) {
        DEBUG("AES Setup SaSi Error: %x\n", ret);
        return SaSi_to_psa_error(ret);
    }

    return PSA_SUCCESS;
}

psa_status_t common_aes_encrypt(SaSiAesUserContext_t *ctx,
                                const uint8_t *input,
                                size_t input_length,
                                uint8_t *output,
                                size_t output_buffer_size,
                                size_t *output_length)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;
    size_t length = input_length;

    do {
        if (length > CC310_MAX_AES_INPUT_BLOCK) {
            size = CC310_MAX_AES_INPUT_BLOCK;
            length -= CC310_MAX_AES_INPUT_BLOCK;
        }
        else {
            size = length;
            length = 0;
        }

        cryptocell_enable();
        ret = SaSi_AesBlock(ctx, (uint8_t *)(input + offset), size, output + offset);
        cryptocell_disable();
        if (ret != SASI_OK) {
            DEBUG("AES Encrypt SaSi Error: %x\n", ret);
            return SaSi_to_psa_error(ret);
        }

        offset += size;
    } while ((length > 0) && (ret == SASI_OK));

    cryptocell_enable();
    ret = SaSi_AesFinish(ctx, length, (uint8_t *)(input + offset), input_length, output,
                         output_length);
    cryptocell_disable();
    if (ret != SASI_OK) {
        DEBUG("AES Encrypt SaSi Error: %x\n", ret);
        return SaSi_to_psa_error(ret);
    }

    (void)output_size;
    return PSA_SUCCESS;
}
