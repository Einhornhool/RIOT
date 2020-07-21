#include <stdint.h>
#include <string.h>

#include "hashes/sha1.h"
#include "sha1_ctx.h"

#include "hwcrypto.h"

#include "periph_conf.h"

#include "xtimer.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

uint32_t t_start[2], t_stop[2];
uint32_t time[5];

hwcrypto_t sha1_dev = HWCRYPTO_DEV(0);

void sha1_init(sha1_context *ctx)
{
    (void) ctx;
    DEBUG("SHA1 init HW accelerated implementation\n");
}

void sha1_update(sha1_context *ctx, const void *data, size_t len)
{
    hwcrypto_acquire(sha1_dev);
    CRYPTO_SHA_1(hwcrypto_config[sha1_dev].dev, (uint8_t*)data, (uint64_t) len, ctx->digest);
    hwcrypto_release(sha1_dev);
}

void sha1_final(sha1_context *ctx, void *digest)
{
    /* Copy the content of the hash (20 characters) */
    memcpy(digest, ctx->digest, 20);
}

void sha1(void *digest, const void *data, size_t len)
{
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_init_hmac(sha1_context *ctx, const void *key, size_t key_length)
{
    (void) ctx;
    (void) (key);
    (void) key_length;
}

void sha1_final_hmac(sha1_context *ctx, void *digest)
{
    (void) ctx;
    (void) digest;
}