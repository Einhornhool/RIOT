/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       this is an ecdh test application
 *
 * @author      Peter Kietzmann <peter.kietzmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>

#include "ps.h"
#include "hashes/sha256.h"
#include "crypto/modes/cbc.h"
#include "random.h"
#include "uECC.h"

#define ECDSA_MESSAGE_SIZE  (127)
#define SHA256_DIGEST_SIZE  (32)
#define CURVE_256_SIZE      (32)
#define PUB_KEY_SIZE        (CURVE_256_SIZE * 2)
#define CIPHER_IV_SIZE      (16)
#define CIPHER_LEN          (32)

static uint8_t KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static uint8_t KEY_LEN = 16;

static uint8_t __attribute__((aligned)) CBC_PLAIN[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t CBC_PLAIN_LEN = 32;

static uint8_t HMAC_KEY[] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static size_t HMAC_KEY_LEN = 64;

static char HMAC_INPUT[] = {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x73, 0x74,
        0x72, 0x69, 0x6e, 0x67, 0x20, 0x66, 0x6f, 0x72,
        0x20, 0x68, 0x6d, 0x61, 0x63, 0x32, 0x35, 0x36
};
static size_t HMAC_INPUT_SIZE = 32;

void _ecdsa(void)
{
    int ret;

    struct uECC_Curve_t *curve;
    uint8_t userPrivKey[CURVE_256_SIZE];
    uint8_t userPubKey[PUB_KEY_SIZE];
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t signature[PUB_KEY_SIZE];

    curve = (struct uECC_Curve_t*)uECC_secp256r1();

    ret = uECC_make_key(userPubKey, userPrivKey, curve);
    if(!ret) {
        puts("ERROR generating Key 1");
        return;
    }

    sha256(msg, ECDSA_MESSAGE_SIZE, hash);

    ret = uECC_sign(userPrivKey, hash, SHA256_DIGEST_SIZE, signature, curve);
    if(ret != 1) {
        puts("ERROR generating shared secret 1");
        return;
    }

    ret = uECC_verify(userPubKey, hash, SHA256_DIGEST_SIZE, signature, curve);
    if(ret != 1) {
        puts("INVALID");
    }
    else
    {
        puts("VALID");
    }
}

void _aes_128(void)
{
    int ret;
    uint8_t iv[CIPHER_IV_SIZE];
    uint8_t cipher[CIPHER_LEN];
    uint8_t plain[CBC_PLAIN_LEN];
    cipher_t ctx;

    random_bytes(iv, CIPHER_IV_SIZE);

    ret = cipher_init(&ctx, CIPHER_AES, KEY, KEY_LEN);
    if (ret < 1) {
        printf("AES CBC Enc Init failed: %d\n", ret);
        return;
    }

    ret = cipher_encrypt_cbc(&ctx, iv, CBC_PLAIN, CBC_PLAIN_LEN, cipher);
    if (ret < 0) {
        printf("AES CBC Encrypt failed: %d\n", ret);
        return;
    }

    ret = cipher_decrypt_cbc(&ctx, iv, cipher, CIPHER_LEN, plain);
    if (ret < 0) {
        printf("AES CBC Decrypt failed: %d\n", ret);
        return;
    }
}

void _hmac_sha256(void)
{
    uint8_t hmac_result[SHA256_DIGEST_LENGTH];
    hmac_context_t ctx;

    hmac_sha256_init(&ctx, HMAC_KEY, HMAC_KEY_LEN);
    hmac_sha256_update(&ctx, HMAC_INPUT, HMAC_INPUT_SIZE );
    hmac_sha256_final(&ctx, hmac_result);
}

int main(void)
{
    _ecdsa();
    _aes_128();
    _hmac_sha256();

    ps();
    return 0;
}