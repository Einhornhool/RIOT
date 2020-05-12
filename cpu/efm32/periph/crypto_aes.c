/*
 * Copyright (C) 2016 Oliver Hahm <oliver.hahm@inria.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/* This code is public-domain - it is based on libcrypt
 * placed in the public domain by Wei Dai and other contributors.
 */

/**
 * @ingroup     sys_hashes_sha1

 * @{
 *
 * @file
 * @brief       Implementation of the SHA-1 hashing function
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "crypto/aes.h"
#include "crypto/ciphers.h"

#include "periph/hwcrypto.h"

#include "mutex.h"
#include "assert.h"

#include "periph_conf.h"
#include "em_cmu.h"
#include "em_crypto.h"
#include "em_device.h"

#include "xtimer.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

hwcrypto_t aes_dev = HWCRYPTO_DEV(0);

/**
 * Interface to the aes cipher
 */
static const cipher_interface_t aes_interface = {
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    aes_init,
    aes_encrypt,
    aes_decrypt
};
const cipher_id_t CIPHER_AES_128 = &aes_interface;

static mutex_t hwcrypto_lock[HWCRYPTO_NUMOF];

void hwcrypto_init(hwcrypto_t dev)
{
    assert(dev < HWCRYPTO_NUMOF);

    /* initialize lock */
    mutex_init(&hwcrypto_lock[dev]);
}

void hwcrypto_acquire(hwcrypto_t dev)
{
    mutex_lock(&hwcrypto_lock[dev]);

    CMU_ClockEnable(cmuClock_HFPER, true);
    CMU_ClockEnable(hwcrypto_config[dev].cmu, true);
}

void hwcrypto_release(hwcrypto_t dev)
{
    CMU_ClockEnable(hwcrypto_config[dev].cmu, false);

    mutex_unlock(&hwcrypto_lock[dev]);
}

int aes_init(cipher_context_t *context, const uint8_t *key, uint8_t keySize)
{
    DEBUG("AES init HW accelerated implementation\n");
    uint8_t i;
    /* This implementation only supports a single key size (defined in AES_KEY_SIZE) */
    if (keySize != AES_KEY_SIZE) {
        return CIPHER_ERR_INVALID_KEY_SIZE;
    }

    /* Make sure that context is large enough. If this is not the case,
       you should build with -DAES */
    if (CIPHER_MAX_CONTEXT_SIZE < AES_KEY_SIZE) {
        return CIPHER_ERR_BAD_CONTEXT_SIZE;
    }

    /* key must be at least CIPHERS_MAX_KEY_SIZE Bytes long */
    if (keySize < CIPHERS_MAX_KEY_SIZE) {
        /* fill up by concatenating key to as long as needed */
        for (i = 0; i < CIPHERS_MAX_KEY_SIZE; i++) {
            context->context[i] = key[(i % keySize)];
        }
    }
    else {
        for (i = 0; i < CIPHERS_MAX_KEY_SIZE; i++) {
            context->context[i] = key[i];
        }
    }
    return CIPHER_INIT_SUCCESS;
}

/*
 * Encrypt a single block
 * in and out can overlap
 */
int aes_encrypt(const cipher_context_t *context, const uint8_t *plainBlock,
                uint8_t *cipherBlock)
{
    hwcrypto_acquire(aes_dev);
    CRYPTO_AES_ECB128(hwcrypto_config[aes_dev].dev, cipherBlock, plainBlock, AES_BLOCK_SIZE, context->context, true);
    hwcrypto_release(aes_dev);
    return 1;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt(const cipher_context_t *context, const uint8_t *cipherBlock,
                uint8_t *plainBlock)
{
    uint32_t sta, sto, dif;
    hwcrypto_acquire(aes_dev);
    uint8_t decrypt_key[AES_KEY_SIZE];
    sta = xtimer_now_usec();
    CRYPTO_AES_DecryptKey128(hwcrypto_config[aes_dev].dev, decrypt_key, context->context);
    sto = xtimer_now_usec();
    dif = sto - sta;
    DEBUG("AES Set decrypt key: %ld\n", dif);
    CRYPTO_AES_ECB128(hwcrypto_config[aes_dev].dev, plainBlock, cipherBlock, AES_BLOCK_SIZE, decrypt_key, false);
    hwcrypto_release(aes_dev);
    return 1;
}
