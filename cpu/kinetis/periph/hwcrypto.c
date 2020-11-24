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

#include "assert.h"

#include "vendor/MKW21D5.h"
#include "periph/hwcrypto.h"

#include "cau_api.h"
#include "mmcau.h"

#define CIPHER_AES_MAXNR       14
#define CIPHER_AES_BLOCK_SIZE  16
#define CIPHER_AES_KEY_SIZE    16

/**
 * @brief   Type definition of the hardware crypto device state.
 */
typedef union {
    struct {
        hwcrypto_cipher_t cipher;
        hwcrypto_mode_t mode;
        uint8_t key[CIPHER_AES_KEY_SIZE] __attribute__((aligned));
        uint32_t rd_key[4 * (CIPHER_AES_MAXNR + 1)] __attribute__((aligned));
        uint8_t rounds;
        union {
            uint8_t iv[16] __attribute__((aligned));
            uint8_t counter[16] __attribute__((aligned));
        } opts;
    } cipher;
    struct {
        hwcrypto_hash_t hash;
        uint8_t initialized;
        uint8_t digest[32] __attribute__((aligned));
    } hash;
} state_t;

/**
 * @brief   Hardware crypto device state.
 */
static state_t state;

void hwcrypto_init(hwcrypto_t dev)
{
    (void) dev;
    /* clear the state */
    memset(&state, 0, sizeof(state_t));
}

int hwcrypto_cipher_init(hwcrypto_t dev, hwcrypto_cipher_t cipher, hwcrypto_mode_t mode)
{
    (void) dev;
    /* check if cipher is supported */
    if (!hwcrypto_cipher_supported(dev, cipher)) {
        return HWCRYPTO_NOTSUP;
    }

    /* initialize state */
    state.cipher.cipher = cipher;
    state.cipher.mode = mode;

    return HWCRYPTO_OK;
}

int hwcrypto_cipher_set(hwcrypto_t dev, hwcrypto_opt_t option, const void *value, uint32_t size)
{
    (void) dev;
    switch (option) {
        case HWCRYPTO_OPT_KEY:
            if (state.cipher.cipher == HWCRYPTO_AES128 && size == CIPHER_AES_KEY_SIZE) {
                cau_aes_set_key(value, CIPHER_AES_KEY_SIZE * 8, (unsigned char*)state.cipher.rd_key);
                state.cipher.rounds = 10;
            }
            else {
                return HWCRYPTO_INVALID;
            }
            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return HWCRYPTO_OK;
}

static int hwcrypto_cipher_encrypt_decrypt(hwcrypto_t dev, const uint8_t *plain_block, uint8_t *cipher_block, uint32_t block_size, bool encrypt)
{
    (void) dev;
    /* blocks must be aligned */
    assert(!((intptr_t) plain_block & 0x03));
    assert(!((intptr_t) cipher_block & 0x03));

    if ((block_size % 16) != 0) {
        return HWCRYPTO_INVALID;
    }

    if (state.cipher.cipher == HWCRYPTO_AES128) {
        if (encrypt) {
            cau_aes_encrypt(plain_block, (unsigned char*)state.cipher.rd_key, state.cipher.rounds, cipher_block);
        }
        else {
            cau_aes_decrypt(cipher_block, (unsigned char*)state.cipher.rd_key, state.cipher.rounds, (uint8_t*)plain_block);
        }
    }
    else {
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
    (void) dev;
    /* check if hash algorithm is supported */
    if (!hwcrypto_hash_supported(dev, hash)) {
        return HWCRYPTO_NOTSUP;
    }

    /* initialize state */
    state.hash.hash = hash;
    state.hash.initialized = 0;

    return HWCRYPTO_OK;
}

int hwcrypto_hash_update(hwcrypto_t dev, const uint8_t *block, uint32_t block_size)
{
    (void) dev;
    (void) block_size;

    switch (state.hash.hash) {
        case HWCRYPTO_SHA1:
            if (!state.hash.initialized) {
                cau_sha1_initialize_output((unsigned int*)state.hash.digest);
                state.hash.initialized = 1;
            }
            else {
                cau_sha1_hash_n(block, 1, (unsigned int*)state.hash.digest);
            }
            break;
        case HWCRYPTO_SHA256:
            if (!state.hash.initialized) {
                cau_sha256_initialize_output((unsigned int*)state.hash.digest);
                state.hash.initialized = 1;
            }
            else {
                cau_sha256_hash_n(block, 1, (unsigned int*)state.hash.digest);
            }
            break;
        default:
            return HWCRYPTO_NOTSUP;
    }

    return block_size;
}

void hwcrypto_return_state(uint32_t* ext_state) {
    memcpy(ext_state, state.hash.digest, 32);
}

int hwcrypto_hash_final(hwcrypto_t dev, uint8_t *result, uint32_t result_size)
{
    (void) dev;
    (void) result;
    (void) result_size;
    return HWCRYPTO_NOTSUP;
}

int hwcrypto_acquire(hwcrypto_t dev)
{
    (void) dev;
    return HWCRYPTO_OK;
}

int hwcrypto_release(hwcrypto_t dev)
{
    (void) dev;
    return HWCRYPTO_OK;
}