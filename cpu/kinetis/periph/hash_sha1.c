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

#include <stdint.h>
#include <string.h>

#include "vendor/MKW21D5.h"
#include "hashes/sha1.h"
#include "mmcau_hash_sha1.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define SHA1_K0  0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

void sha1_init(sha1_context *ctx)
{
    DEBUG("SHA1 init HW accelerated implementation\n");
    /* Initialize hash variables */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->byte_count = 0;
    ctx->buffer_offset = 0;
}

static int check_index(int ind, int off)
{
    return ((ind + off) >= 16) ? ((ind + off) % 16) : (ind + off);
}

static void sha1_step(int count, int func, int *i, int constant, sha1_context *ctx)
{
    int index = check_index(*i, 0);
    int temp;
    printf("index: %d\n", index);
    for (int j = 0; j < count; j++) {
            CAU->DIRECT[0] = MMCAU_2_CMDS((HASH+func), (ADRA+CA4));
            CAU->ADR_CAA = constant;
            CAU->LDR_CA[5] = ctx->buffer[index];
            temp = check_index(*i, 2);
            printf("temp + 2: %d\n", temp);
            CAU->XOR_CA[5] = ctx->buffer[temp];
            temp = check_index(*i, 8);
            printf("temp + 8: %d\n", temp);
            CAU->XOR_CA[5] = ctx->buffer[temp];
            temp = check_index(*i, 13);
            printf("temp + 13: %d\n", temp);
            CAU->XOR_CA[5] = ctx->buffer[temp];
            CAU->ROTL_CA[5] = 1;
            ctx->buffer[index % 16] = CAU->STR_CA[5];
            index++;
            CAU->DIRECT[0] = MMCAU_2_CMDS((ADRA+CA5), SHS);
        }
    *i = index;
}

static void sha1_hash_block(sha1_context *ctx)
{
    int j;
    int i = 0;
    for (j = 0; j < 5; j++) {
        CAU->LDR_CA[j] = ctx->state[j];
    }

    CAU->DIRECT[0] = MMCAU_1_CMD((MVRA+CA0));       /* a -> CAA */
    CAU->ROTL_CAA = 5;                              /* rotate 5 */

    for (j = 0; j < 16; j++) {
        CAU->DIRECT[0] = MMCAU_2_CMDS((HASH+HFC), (ADRA+CA4));
        CAU->ADR_CAA = SHA1_K0;
        CAU->ADR_CAA = ctx->buffer[i++];
        CAU->DIRECT[0] = MMCAU_1_CMD(SHS);
    }

    sha1_step(4, HFC, &i, SHA1_K0, ctx);
    sha1_step(20, HFP, &i, SHA1_K20, ctx);
    sha1_step(20, HFM, &i, SHA1_K40, ctx);
    sha1_step(20, HFP, &i, SHA1_K60, ctx);

    for (j = 0; j < 5; j++) {
        CAU->ADR_CA[j] = ctx->state[j];
    }
    for (j = 4; j >= 0; j--) {
        ctx->state[j] = CAU->STR_CA[j];
    }
}

static void sha1_add_uncounted(sha1_context *s, uint8_t data)
{
    uint8_t *const b = (uint8_t *) s->buffer;

#ifdef __BIG_ENDIAN__
    b[s->buffer_offset] = data;
#else
    b[s->buffer_offset ^ 3] = data;
#endif
    s->buffer_offset++;
    if (s->buffer_offset == SHA1_BLOCK_LENGTH) {
        sha1_hash_block(s);
        s->buffer_offset = 0;
    }
}

static void sha1_update_byte(sha1_context *ctx, uint8_t data)
{
    ++ctx->byte_count;
    sha1_add_uncounted(ctx, data);
}

void sha1_update(sha1_context *ctx, const void *data, size_t len)
{
    const uint8_t *d = data;
    while (len--) {
        sha1_update_byte(ctx, *(d++));
    }
}

static void sha1_pad(sha1_context *s)
{
    /* Implement SHA-1 padding (fips180-2 §5.1.1) */
    /* Pad with 0x80 followed by 0x00 until the end of the block */
    sha1_add_uncounted(s, 0x80);
    while (s->buffer_offset != 56) {
        sha1_add_uncounted(s, 0x00);
    }

    /* Append length in the last 8 bytes */
    sha1_add_uncounted(s, 0);                   /* We're only using 32 bit lengths */
    sha1_add_uncounted(s, 0);                   /* But SHA-1 supports 64 bit lengths */
    sha1_add_uncounted(s, 0);                   /* So zero pad the top bits */
    sha1_add_uncounted(s, s->byte_count >> 29); /* Shifting to multiply by 8 */
    sha1_add_uncounted(s, s->byte_count >> 21); /* as SHA-1 supports bitstreams as well as */
    sha1_add_uncounted(s, s->byte_count >> 13); /* byte. */
    sha1_add_uncounted(s, s->byte_count >> 5);
    sha1_add_uncounted(s, s->byte_count << 3);
}

void sha1_final(sha1_context *ctx, void *digest)
{
    /* Pad to complete the last block */
    sha1_pad(ctx);

    /* Swap byte order back */
    for (int i = 0; i < 5; i++) {
        ctx->state[i] =
            (((ctx->state[i]) << 24) & 0xff000000)
            | (((ctx->state[i]) << 8) & 0x00ff0000)
            | (((ctx->state[i]) >> 8) & 0x0000ff00)
            | (((ctx->state[i]) >> 24) & 0x000000ff);
    }

    /* Copy the content of the hash (20 characters) */
    memcpy(digest, ctx->state, 20);
}

void sha1(void *digest, const void *data, size_t len)
{
    sha1_context ctx;

    sha1_init(&ctx);
    sha1_update(&ctx, (unsigned char *) data, len);
    sha1_final(&ctx, digest);
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_init_hmac(sha1_context *ctx, const void *key, size_t key_length)
{
    uint8_t i;
    const uint8_t *k = key;

    memset(ctx->key_buffer, 0, SHA1_BLOCK_LENGTH);
    if (key_length > SHA1_BLOCK_LENGTH) {
        /* Hash long keys */
        sha1_init(ctx);
        while (key_length--) {
            sha1_update_byte(ctx, *k++);
        }
        sha1_final(ctx, ctx->key_buffer);
    }
    else {
        /* Block length keys are used as is */
        memcpy(ctx->key_buffer, key, key_length);
    }
    /* Start inner hash */
    sha1_init(ctx);
    for (i = 0; i < SHA1_BLOCK_LENGTH; i++) {
        sha1_update_byte(ctx, ctx->key_buffer[i] ^ HMAC_IPAD);
    }
}

void sha1_final_hmac(sha1_context *ctx, void *digest)
{
    uint8_t i;

    /* Complete inner hash */
    sha1_final(ctx, ctx->inner_hash);
    /* Calculate outer hash */
    sha1_init(ctx);
    for (i = 0; i < SHA1_BLOCK_LENGTH; i++) {
        sha1_update_byte(ctx, ctx->key_buffer[i] ^ HMAC_OPAD);
    }
    for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        sha1_update_byte(ctx, ctx->inner_hash[i]);
    }

    sha1_final(ctx, digest);
}
