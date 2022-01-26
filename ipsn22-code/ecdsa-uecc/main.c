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
#include "uECC.h"

#define ECDSA_MESSAGE_SIZE  (127)
#define SHA256_DIGEST_SIZE  (32)
#define CURVE_256_SIZE      (32)
#define PUB_KEY_SIZE        (CURVE_256_SIZE * 2)

static const uint8_t l_private[] = {
    0x9b, 0x4c, 0x4b, 0xa0, 0xb7, 0xb1, 0x25, 0x23,
    0x9c, 0x09, 0x85, 0x4f, 0x9a, 0x21, 0xb4, 0x14,
    0x70, 0xe0, 0xce, 0x21, 0x25, 0x00, 0xa5, 0x62,
    0x34, 0xa4, 0x25, 0xf0, 0x0f, 0x00, 0xeb, 0xe7,
};
static const uint8_t l_public[] = {
    0x54, 0x3e, 0x98, 0xf8, 0x14, 0x55, 0x08, 0x13,
    0xb5, 0x1a, 0x1d, 0x02, 0x02, 0xd7, 0x0e, 0xab,
    0xa0, 0x98, 0x74, 0x61, 0x91, 0x12, 0x3d, 0x96,
    0x50, 0xfa, 0xd5, 0x94, 0xa2, 0x86, 0xa8, 0xb0,
    0xd0, 0x7b, 0xda, 0x36, 0xba, 0x8e, 0xd3, 0x9a,
    0xa0, 0x16, 0x11, 0x0e, 0x1b, 0x6e, 0x81, 0x13,
    0xd7, 0xf4, 0x23, 0xa1, 0xb2, 0x9b, 0xaf, 0xf6,
    0x6b, 0xc4, 0x2a, 0xdf, 0xbd, 0xe4, 0x61, 0x5c,
};

typedef struct uECC_SHA256_HashContext {
    uECC_HashContext uECC;
    sha256_context_t ctx;
} uECC_SHA256_HashContext;

struct uECC_Curve_t *curve;
// uint8_t userPrivKey1[CURVE_256_SIZE];
// uint8_t userPubKey1[PUB_KEY_SIZE];

static uint8_t tmp[2 * SHA256_DIGEST_LENGTH + SHA256_INTERNAL_BLOCK_SIZE];

static void _init_sha256(const uECC_HashContext *base)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_init(&context->ctx);
}

static void _update_sha256(const uECC_HashContext *base,
                          const uint8_t *message,
                          unsigned message_size)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void _finish_sha256(const uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}

void _init_curve(void)
{
    curve = (struct uECC_Curve_t*)uECC_secp256r1();
}

// void _gen_keypair(void)
// {
//     int ret;
//     ret = uECC_make_key(userPubKey1, userPrivKey1, curve);
//     if(!ret) {
//         puts("ERROR generating Key 1");
//         return;
//     }
// }

void _sign_verify(void)
{
    int ret;

    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t signature[PUB_KEY_SIZE];

    sha256(msg, ECDSA_MESSAGE_SIZE, hash);

    uECC_SHA256_HashContext ctx;
    ctx.uECC.init_hash = &_init_sha256;
    ctx.uECC.update_hash = &_update_sha256;
    ctx.uECC.finish_hash = &_finish_sha256;
    ctx.uECC.block_size = 64;
    ctx.uECC.result_size = 32;
    ctx.uECC.tmp = tmp;

    ret = uECC_sign_deterministic(l_private, hash, SHA256_DIGEST_SIZE, &ctx.uECC, signature, curve);
    if(ret != 1) {
        puts("ERROR generating shared secret 1");
        return;
    }

    ret = uECC_verify(l_public, hash, SHA256_DIGEST_SIZE, signature, curve);
    if(ret != 1) {
        puts("INVALID");
    }
    else
    {
        puts("VALID");
    }
}


int main(void)
{
    puts("'crypto-ewsn2020_ecdsa'");

    for (int i = 0; i < 1; i++){
        _init_curve();
        // generate two instances of keypairs
        // _gen_keypair();

        // derive and compare secrets generated on both
        _sign_verify();
    }

    ps();
    puts("DONE");
    return 0;
}