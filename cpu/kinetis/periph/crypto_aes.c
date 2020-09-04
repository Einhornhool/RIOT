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
#include "aes_hwctx.h"
#include "cau_api.h"

#include "vendor/MKW21D5.h"
#include "mmcau.h"
#include "xtimer.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"


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
#if 0
    if ((unsigned int)cipherBlock % 4) {
        puts("cipherBlock Bad cau_aes_encrypt alignment!!!");
    }
    if ((unsigned int)plainBlock % 4) {
        puts("plainBlock Bad cau_aes_encrypt alignment!!!");
    }
#endif
    AES_KEY aeskey;
    AES_KEY* key = &aeskey;
    cau_aes_set_key((unsigned char *)context->context,
                              AES_KEY_SIZE * 8, (unsigned char*)key->rd_key);
    /* Currently only AES-128 is implemented, so the number of rounds is always 10 */
    key->rounds = 10;

    cau_aes_encrypt(plainBlock, (unsigned char*)key->rd_key, key->rounds, cipherBlock);
    return 1;
}

/*
 * Decrypt a single block
 * in and out can overlap
 */
int aes_decrypt(const cipher_context_t *context, const uint8_t *cipherBlock,
                uint8_t *plainBlock)
{
    AES_KEY aeskey;
    AES_KEY *key = &aeskey;
    cau_aes_set_key((unsigned char *)context->context,
                              AES_KEY_SIZE * 8, (unsigned char*)key->rd_key);
    /* Currently only AES-128 is implemented, so the number of rounds is always 10 */
    key->rounds = 10;

    cau_aes_decrypt(cipherBlock, (unsigned char*)key->rd_key, key->rounds, plainBlock);

    return 1;
}
