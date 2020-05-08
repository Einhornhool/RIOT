/*
 * Copyright (C) 2014 Freie Universität Berlin
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
 * @brief       Hello World application
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include "crypto/aes.h"
#include "crypto/ciphers.h"
#include "tinycrypt/aes.h"
#include "aes.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "user_settings.h"
#include "em_device.h"
#include "em_crypto.h"
#include "xtimer.h"

/* AES Test */
static uint8_t TEST_0_KEY[] = {
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF
};

static uint8_t TEST_0_INP[] = {
    0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
};
static uint8_t TEST_0_ENC[] = {
    0x37, 0x29, 0xa3, 0x6c, 0xaf, 0xe9, 0x84, 0xff,
    0x46, 0x22, 0x70, 0x42, 0xee, 0x24, 0x83, 0xf6
};

/* Timer variables */
uint32_t t_start, t_stop, time_diff;

static void riot_aes(void)
{
    printf("RIOT AES\n");
    /* Time measurements happen in AES functions*/
    cipher_context_t c_ctx;
    uint8_t data[_AES_BLOCK_SIZE] = {0x00};
    memset(data, 0, _AES_BLOCK_SIZE);
    aes_init(&c_ctx, TEST_0_KEY, sizeof(TEST_0_KEY));
    aes_encrypt(&c_ctx, TEST_0_INP, data);
    if (memcmp(data, TEST_0_ENC, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }
    memset(data, 0, _AES_BLOCK_SIZE);
    aes_decrypt(&c_ctx, TEST_0_ENC, data);
    if (memcmp(data, TEST_0_INP, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }
    printf("\n");
}

static void tinycrypt_aes(void)
{
    printf("Tinycrypt AES\n");
    struct tc_aes_key_sched_struct s;

    /* some memory to store the encrypted data (add '\0` termination)*/
    uint8_t cipher[TC_AES_BLOCK_SIZE + 1];
    uint8_t result[TC_AES_BLOCK_SIZE + 1];
    memset(cipher, 0, TC_AES_BLOCK_SIZE + 1);
    memset(result, 0, TC_AES_BLOCK_SIZE + 1);

    /* Initialize Key */
    t_start = xtimer_now_usec();
    tc_aes128_set_encrypt_key(&s, TEST_0_KEY);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("TC set encrypt key: %ld us\n", time_diff);

    /* encrypt data */
    t_start = xtimer_now_usec();
    tc_aes_encrypt(cipher, TEST_0_INP, &s);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("TC encrypt: %ld us\n", time_diff);
    if (memcmp(cipher, TEST_0_ENC, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }

    /* decrypt data again */
    t_start = xtimer_now_usec();
    tc_aes128_set_decrypt_key(&s, TEST_0_KEY);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("TC set decrypt key: %ld us\n", time_diff);

    t_start = xtimer_now_usec();
    tc_aes_decrypt(result, cipher, &s);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("TC decrypt: %ld us\n", time_diff);
    if (memcmp(result, TEST_0_INP, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }
    printf("\n");
}

static void wolfssl_aes(void)
{
    printf("wolfSSL AES\n");
    Aes enc;
    Aes dec;

    const uint8_t iv[16] = { 0x00 };

    uint8_t cipher[32];
    uint8_t result[32];

    /* encryption */
    t_start = xtimer_now_usec();
    wc_AesSetKey(&enc, TEST_0_KEY, sizeof(TEST_0_KEY), iv, AES_ENCRYPTION);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("Set Encrption Key: %ld us\n", time_diff);

    t_start = xtimer_now_usec();
    wc_AesEncryptDirect(&enc, cipher, TEST_0_INP);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("Encrypt: %ld us\n", time_diff);
    if (memcmp(cipher, TEST_0_ENC, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }

    /* decryption */
    t_start = xtimer_now_usec();
    wc_AesSetKey(&dec, TEST_0_KEY, sizeof(TEST_0_KEY), iv, AES_DECRYPTION);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("Set Decrypt Key: %ld us\n", time_diff);

    t_start = xtimer_now_usec();
    wc_AesDecryptDirect(&dec, result, cipher);
    t_stop = xtimer_now_usec();
    time_diff = t_stop - t_start;
    printf("Decryption: %ld us\n", time_diff);
    if (memcmp(result, TEST_0_INP, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED\n");
    }
    printf("\n");
}

static void gecko_hw_aes(void)
{
    uint8_t cipher[32];
    uint8_t result[32];

    CRYPTO_AES_ECB128(CRYPTO, cipher, TEST_0_INP, AES_BLOCK_SIZE, TEST_0_KEY, true);
    if (memcmp(cipher, TEST_0_ENC, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED: %02x %02x %02x %02x\n", cipher[0], cipher[1], cipher[2], cipher[3]);
    }

    CRYPTO_AES_ECB128(CRYPTO, result, TEST_0_ENC, AES_BLOCK_SIZE, TEST_0_KEY, false);
    if (memcmp(result, TEST_0_INP, _AES_BLOCK_SIZE) != 0) {
        printf("FAILED: %02x %02x %02x %02x\n", result[0], result[1], result[2], result[3]);
    }
}

int main(void)
{
    puts("Hello World!");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    riot_aes();
    tinycrypt_aes();
    wolfssl_aes();
    gecko_hw_aes();
    return 0;
}
