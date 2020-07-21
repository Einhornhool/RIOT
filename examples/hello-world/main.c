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
#include <stdint.h>
#include <string.h>

#include "periph/hwcrypto.h"
#ifdef MODULE_GECKO_SDK
#include "em_device.h"
#include "em_crypto.h"
#endif

#ifdef NRF52840_XXAA
// #include "vendor/nrf52840.h"
#include "sdk_common.h"
#include "nrf_crypto.h"
#include "nrf_crypto_error.h"
#include "nrf_crypto_hash.h"
#include "mem_manager.h"
#endif

#ifdef ARM_CRYPTOCELL
#include "armcc_setup.h"
#endif

#include "hashes/sha1.h"
#include "hashes/sha256.h"
#include "crypto/aes.h"
#include "crypto/ciphers.h"
#include "xtimer.h"
#include "periph_conf.h"

/* SHA Tests */
uint8_t sha1_result[SHA1_DIGEST_LENGTH];
uint8_t sha256_result[SHA256_DIGEST_LENGTH];
char teststring[] = "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, pellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec, vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu pede mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellus. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra quis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ultricies nisi vel augue";
uint8_t expected_result_sha1[] = { 0x6a, 0x7c, 0x17, 0x10, 0x4e, 0x56, 0x13, 0xa6, 0x82, 0xc5, 0x2b, 0x84, 0x54, 0xae, 0x5e, 0xbc, 0x9e, 0x8a, 0xf1, 0x67 };

uint8_t expected_result_sha256[] = { 0xfc, 0xbd, 0x7f, 0xe5, 0x12, 0x31, 0x1d, 0x1a, 0x19, 0x33, 0x87, 0x9a, 0x81, 0xe3, 0x42, 0x2e, 0x47, 0x4d, 0xf3, 0xd2, 0x46, 0xdf, 0x82, 0xdf, 0x3f, 0x63, 0x4a, 0xe1, 0x39, 0xd3, 0xb0, 0xa6 };

size_t teststring_size = (sizeof(teststring)-1);

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
uint32_t start, stop, t_diff;

#ifdef NRF52840_XXAA
    static void nrf_sdk_sha256(void)
    {
        nrf_crypto_hash_context_t ctx;
        nrf_crypto_hash_sha256_digest_t result;
        size_t result_len = NRF_CRYPTO_HASH_SIZE_SHA256;

        start = xtimer_now_usec();
        if (nrf_crypto_hash_init(&ctx, &g_nrf_crypto_hash_sha256_info)) {
            printf("CC310 Sha256 Init failed\n");
        }
        if (nrf_crypto_hash_update(&ctx, (uint8_t*) teststring, teststring_size)) {
            printf("CC310 Sha256 Update failed\n");
        }
        if (nrf_crypto_hash_finalize(&ctx, result, &result_len)) {
            printf("CC310 Sha256 finish failed\n");
        }
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("CC310 Sha256 Time: %ld us\n", t_diff);

        if (memcmp((uint8_t*)result, expected_result_sha256, SHA256_DIGEST_LENGTH) != 0) {
                printf("CC310 SHA-256 Failure\n");

                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    printf("%02x ", sha256_result[i]);
                }
                printf("\n");
        }
        else {
            printf("CC310 SHA-256 Success\n");
        }
    }

    static void nrf_sdk_aes(void)
    {
        nrf_crypto_aes_context_t enc, dec;

        uint8_t data[AES_BLOCK_SIZE];
        size_t data_size = 16;

        if (nrf_crypto_aes_init(&enc, &g_nrf_crypto_aes_ecb_128_info, NRF_CRYPTO_ENCRYPT)) {
            printf("CC310 AES encrypt init failed\n");
        }
        if (nrf_crypto_aes_init(&dec, &g_nrf_crypto_aes_ecb_128_info, NRF_CRYPTO_DECRYPT)) {
            printf("CC310 AES decrypt init failed\n");
        }

        /* Encryption */
        start = xtimer_now_usec();
        if (nrf_crypto_aes_key_set(&enc, TEST_0_KEY)) {
            printf("CC310 AES set encrypt key failed\n");
        }
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("CC310 AES set encrypt key time: %ld us\n", t_diff);

        start = xtimer_now_usec();
        if (nrf_crypto_aes_finalize(&enc, TEST_0_INP, sizeof(TEST_0_INP), data, &data_size)) {
            printf("CC310 AES encrypt failed\n");
        }
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("CC310 AES encryption time: %ld us\n", t_diff);
        if (!memcmp(data, TEST_0_ENC, AES_BLOCK_SIZE)) {
            printf("CC310 AES encryption successful\n");
        }
        else {
            printf("CC310 AES encryption failed\n");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
        }

        /* Decryption */
        start = xtimer_now_usec();
        if (nrf_crypto_aes_key_set(&dec, TEST_0_KEY)) {
            printf("CC310 AES set decrypt key failed\n");
        }
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("CC310 AES set decrypt key time: %ld us\n", t_diff);

        start = xtimer_now_usec();
        if (nrf_crypto_aes_finalize(&dec, TEST_0_ENC, sizeof(TEST_0_ENC), data, &data_size)) {
            printf("CC310 AES decrypt failed\n");
        }
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("CC310 AES decryption time: %ld us\n", t_diff);
        if (!memcmp(data, TEST_0_INP, AES_BLOCK_SIZE)) {
            printf("CC310 AES decryption successful\n");
        }
        else {
            printf("CC310 AES decryption failed\n");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
        }
    }
#endif

static void sha1_test(void)
{
    #ifdef FREESCALE_MMCAU
        printf("MMCAU Sha1\n");
    #elif MODULE_GECKO_SDK
        printf("Gecko SDK Sha1\n");
    #endif
    start = xtimer_now_usec();
    sha1(sha1_result, (unsigned char*)teststring, teststring_size);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("Sha1 Time: %ld us\n", t_diff);

    if (memcmp(sha1_result, expected_result_sha1, SHA1_DIGEST_LENGTH) != 0) {
        printf("SHA-1 Failure\n");

        for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
            printf("%02x ", sha1_result[i]);
        }
        printf("\n");
    }
    else {
        printf("SHA-1 Success\n");
    }
}

static void sha256_test(void)
{
    start = xtimer_now_usec();
    sha256((unsigned char*)teststring, teststring_size, sha256_result);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("Sha256 Time: %ld us\n", t_diff);

    if (memcmp(sha256_result, expected_result_sha256, SHA256_DIGEST_LENGTH) != 0) {
        printf("SHA-256 Failure\n");

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x ", sha256_result[i]);
        }
        printf("\n");
    }
    else {
        printf("SHA-256 Success\n");
    }
}

static void aes_test(void)
{
    int err;
    cipher_context_t c_ctx;
    uint8_t data[AES_BLOCK_SIZE];
    memset(data, 0, AES_BLOCK_SIZE);

    err = aes_init(&c_ctx, TEST_0_KEY, AES_KEY_SIZE);
    if (err < 1) {
        printf("AES Init failed: %d\n", err);
    }

    start = xtimer_now_usec();
    if (aes_encrypt(&c_ctx, TEST_0_INP, data)) {
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("AES Encrypt time: %ld us\n", t_diff);
        if (!memcmp(data, TEST_0_ENC, AES_BLOCK_SIZE)) {
            printf("AES encryption successful\n");
        }
        else
        {
            printf("AES encryption failed\n");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
        }
    }
    memset(data, 0, AES_BLOCK_SIZE);
    start = xtimer_now_usec();
    if (aes_decrypt(&c_ctx, TEST_0_ENC, data)) {
        stop = xtimer_now_usec();
        t_diff = stop - start;
        printf("AES Decrypt time: %ld us\n", t_diff);
        if (!memcmp(data, TEST_0_INP, AES_BLOCK_SIZE)) {
            printf("AES decryption successful\n");
        }
        else
        {
            printf("AES decryption failed\n");
            for (int i = 0; i < 16; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
        }
    }
}
// #endif

int main(void)
{
    puts("Hello World!");
    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    /*There are some internal time measurements in the SHA-1 and AES
    Algorithms, which can be activated by setting the ENABLE_DEBUG flag
    in the API Because of the internal printfs his makes the hashing
    and encryption much slower, though. */
#ifdef NRF52840_XXAA
    // Initialize crypto subsystem
    if (nrf_crypto_init() != NRF_SUCCESS) {
        printf("Error initializing nrf backend\n");
    }
    if (nrf_mem_init() != NRF_SUCCESS) {
        printf("Error initializing nrf memory\n");
    }
    nrf_sdk_sha256();
    nrf_sdk_aes();
#elif ARM_CRYPTOCELL
    cryptocell_setup();
    sha1_test();
    sha256_test();
    aes_test();
    cryptocell_finish();
#else
    sha1_test();
    sha256_test();
    aes_test();
#endif
    return 0;
}
