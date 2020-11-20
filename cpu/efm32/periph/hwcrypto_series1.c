/*
 * Copyright (C) 2016-2018 Bas Stottelaar <basstottelaar@gmail.com>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_efm32
 * @ingroup     drivers_periph_hwcrypto
 *
 * @{
 *
 * @file
 * @brief       Low-level hardware crypto driver implementation for EFM32
 *              Series 1 MCUs
 *
 * @author      Bas Stottelaar <basstottelaar@gmail.com>
 *
 * @}
 */

#include <string.h>

#include "mutex.h"
#include "assert.h"

#include "periph/hwcrypto.h"

#include "em_cmu.h"
#include "em_crypto.h"

#define AES_128_KEY_SIZE    (16)

/**
 * @brief   Type definition of the hardware crypto device state.
 */
typedef union {
    struct {
        hwcrypto_cipher_t cipher;
        hwcrypto_mode_t mode;
        uint8_t key[32] __attribute__((aligned));
        union {
            uint8_t iv[16] __attribute__((aligned));
            uint8_t counter[16] __attribute__((aligned));
        } opts;
    } cipher;
    struct {
        hwcrypto_hash_t hash;
        uint8_t digest[32] __attribute__((aligned));
    } hash;
} state_t;

/**
 * @brief   Global lock to ensure mutual exclusive access to crypto hardware.
 */
static mutex_t hwcrypto_lock[HWCRYPTO_NUMOF];

/**
 * @brief   Hardware crypto device state.
 */
static state_t state[HWCRYPTO_NUMOF];

void hwcrypto_init(hwcrypto_t dev)
{
    assert(dev < HWCRYPTO_NUMOF);

    /* initialize lock */
    mutex_init(&hwcrypto_lock[dev]);

    /* clear the state */
    memset(&state[dev], 0, sizeof(state_t));
}

int hwcrypto_cipher_init(hwcrypto_t dev, hwcrypto_cipher_t cipher, hwcrypto_mode_t mode)
{
    /* check if cipher is supported */
    if (!hwcrypto_cipher_supported(dev, cipher)) {
        return HWCRYPTO_NOTSUP;
    }

    /* initialize state */
    state[dev].cipher.cipher = cipher;
    state[dev].cipher.mode = mode;

    return HWCRYPTO_OK;
}

int hwcrypto_cipher_set(hwcrypto_t dev, hwcrypto_opt_t option, const void *value, uint32_t size)
{
    switch (option) {
        case HWCRYPTO_OPT_KEY:
            if (state[dev].cipher.cipher == HWCRYPTO_AES128 && size == 16) {
                memcpy(state[dev].cipher.key, value, 16);
            }
            else if (state[dev].cipher.cipher == HWCRYPTO_AES256 && size == 32) {
                memcpy(state[dev].cipher.key, value, 32);
            }
            else {
                return HWCRYPTO_INVALID;
            }

            break;
        case HWCRYPTO_OPT_IV:
            if (state[dev].cipher.mode != HWCRYPTO_MODE_CBC &&
                state[dev].cipher.mode != HWCRYPTO_MODE_OFB &&
                state[dev].cipher.mode != HWCRYPTO_MODE_CFB
                ) {
                return HWCRYPTO_NOTSUP;
            }

            if (size != 16) {
                return HWCRYPTO_INVALID;
            }

            memcpy(state[dev].cipher.opts.iv, value, 16);
            break;
        case HWCRYPTO_OPT_COUNTER:
            if (state[dev].cipher.mode != HWCRYPTO_MODE_CTR) {
                return HWCRYPTO_NOTSUP;
            }

            if (size != 16) {
                return HWCRYPTO_INVALID;
            }

            memcpy(state[dev].cipher.opts.counter, value, 16);
            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return HWCRYPTO_OK;
}

static int hwcrypto_cipher_encrypt_decrypt(hwcrypto_t dev, const uint8_t *plain_block, uint8_t *cipher_block, uint32_t block_size, bool encrypt)
{
    /* blocks must be aligned */
    assert(!((intptr_t) plain_block & 0x03));
    assert(!((intptr_t) cipher_block & 0x03));

    if ((block_size % 16) != 0) {
        return HWCRYPTO_INVALID;
    }
    if (encrypt == false && ((state[dev].cipher.mode == HWCRYPTO_MODE_ECB) || (state[dev].cipher.mode == HWCRYPTO_MODE_CBC))) {
        uint8_t decrypt_key[AES_128_KEY_SIZE];
        CRYPTO_AES_DecryptKey128(hwcrypto_config[dev].dev, decrypt_key, state[dev].cipher.key);

        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, decrypt_key, AES_128_KEY_SIZE);
    }

    switch (state[dev].cipher.cipher) {
        case HWCRYPTO_AES128:
            switch (state[dev].cipher.mode) {
                case HWCRYPTO_MODE_ECB:
                    CRYPTO_AES_ECB128(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, encrypt);
                    break;
                case HWCRYPTO_MODE_CBC:
                    CRYPTO_AES_CBC128(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv, encrypt);
                    break;
                case HWCRYPTO_MODE_CFB:
                    CRYPTO_AES_CFB128(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv, encrypt);
                    break;
                case HWCRYPTO_MODE_OFB:
                    CRYPTO_AES_OFB128(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv);
                    break;
                case HWCRYPTO_MODE_CTR:
                    CRYPTO_AES_CTR128(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.counter, NULL);
                    break;
                default:
                    return HWCRYPTO_NOTSUP;
            }

            break;
        case HWCRYPTO_AES256:
            switch (state[dev].cipher.mode) {
                case HWCRYPTO_MODE_ECB:
                    CRYPTO_AES_ECB256(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, encrypt);
                    break;
                case HWCRYPTO_MODE_CBC:
                    CRYPTO_AES_CBC256(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv, encrypt);
                    break;
                case HWCRYPTO_MODE_CFB:
                    CRYPTO_AES_CFB256(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv, encrypt);
                    break;
                case HWCRYPTO_MODE_OFB:
                    CRYPTO_AES_OFB256(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.iv);
                    break;
                case HWCRYPTO_MODE_CTR:
                    CRYPTO_AES_CTR256(hwcrypto_config[dev].dev, cipher_block, plain_block, block_size, state[dev].cipher.key, state[dev].cipher.opts.counter, NULL);
                    break;
                default:
                    return HWCRYPTO_NOTSUP;
            }

            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return block_size;
}

int hwcrypto_cipher_encrypt(hwcrypto_t dev, const uint8_t *plain_block, uint8_t *cipher_block, uint32_t block_size)
{
    return hwcrypto_cipher_encrypt_decrypt(dev, plain_block, cipher_block, block_size, true);
}

int hwcrypto_cipher_decrypt(hwcrypto_t dev, const uint8_t *cipher_block, uint8_t *plain_block, uint32_t block_size)
{
    return hwcrypto_cipher_encrypt_decrypt(dev, cipher_block, plain_block, block_size, false);
}

int hwcrypto_hash_init(hwcrypto_t dev, hwcrypto_hash_t hash)
{
    /* check if hash algorithm is supported */
    if (!hwcrypto_hash_supported(dev, hash)) {
        return HWCRYPTO_NOTSUP;
    }

    /* initialize state */
    state[dev].hash.hash = hash;

    return HWCRYPTO_OK;
}

int hwcrypto_hash_update(hwcrypto_t dev, const uint8_t *block, uint32_t block_size)
{
    switch (state[dev].hash.hash) {
        case HWCRYPTO_SHA1:
            CRYPTO_SHA_1(hwcrypto_config[dev].dev, block, block_size, state[dev].hash.digest);
            break;
        case HWCRYPTO_SHA256:
            CRYPTO_SHA_256(hwcrypto_config[dev].dev, block, block_size, state[dev].hash.digest);
            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return block_size;
}

int hwcrypto_hash_final(hwcrypto_t dev, uint8_t *result, uint32_t result_size)
{
    switch (state[dev].hash.hash) {
        case HWCRYPTO_SHA1:
            if (result_size > sizeof(CRYPTO_SHA1_Digest_TypeDef)) {
                return HWCRYPTO_INVALID;
            }

            memcpy(result, state[dev].hash.digest, result_size);
            break;
        case HWCRYPTO_SHA256:
            if (result_size > sizeof(CRYPTO_SHA256_Digest_TypeDef)) {
                return HWCRYPTO_INVALID;
            }

            memcpy(result, state[dev].hash.digest, result_size);
            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return result_size;
}

int hwcrypto_acquire(hwcrypto_t dev)
{
    mutex_lock(&hwcrypto_lock[dev]);

    CMU_ClockEnable(cmuClock_HFPER, true);
    CMU_ClockEnable(hwcrypto_config[dev].cmu, true);

    return HWCRYPTO_OK;
}

int hwcrypto_release(hwcrypto_t dev)
{
    CMU_ClockEnable(hwcrypto_config[dev].cmu, false);

    mutex_unlock(&hwcrypto_lock[dev]);

    return HWCRYPTO_OK;
}