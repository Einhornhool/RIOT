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

#include <stdint.h>
#include "periph/hwcrypto.h"

#if AES
#ifdef BOARD_PBA_D_01_KW2X
#include "crypto/ciphers.h"
#include "crypto/modes/cbc.h"
#include "crypto/modes/ecb.h"
#else
#include "em_crypto.h"
#endif
#endif

#if TEST_STACK
#include "ps.h"
#endif

#if SHA256
#ifdef BOARD_PBA_D_01_KW2X
#include "hashes/sha256.h"
#endif
#endif

#if !defined(TEST_STACK) && !defined(TEST_MEM)

#include <stdio.h>
#include <string.h>

#if !defined(USE_TIMER)
#include "periph/gpio.h"

gpio_t active_gpio = GPIO_PIN(2, 6);
gpio_t acq_rel_gpio = GPIO_PIN(2, 7);
#else
#include "xtimer.h"

/* Timer variables */
uint32_t start;
#endif /* USE_TIMER */

#endif /* TEST_STACK */

#ifdef BOARD_SLSTK3402A
hwcrypto_t dev = HWCRYPTO_DEV(0);
#endif

#if SHA256
#define SHA256_DIGEST_SIZE  (32)
/* SHA Tests */
#ifdef INPUT_512
    static unsigned char SHA_TESTSTRING[] = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Ste";
    static size_t SHA_TESTSTR_SIZE = 512;
#if !defined(TEST_STACK) && !defined(TEST_MEM)
    static uint8_t EXPECTED_RESULT_SHA256[] = {
        0xB5, 0xB7, 0x56, 0xD2, 0x6F, 0x8C, 0xDF, 0x6B,
        0xA3, 0xCC, 0xB8, 0x12, 0x5C, 0xE4, 0x4D, 0x0F,
        0xDD, 0x1C, 0x4C, 0xF1, 0x6E, 0x41, 0x9F, 0xED,
        0x52, 0x79, 0x2E, 0x1A, 0x9C, 0x47, 0xDF, 0x2B
    };
#endif /* TEST_STACK */
#else
    static const unsigned char SHA_TESTSTRING[] = "This is a teststring fore sha256";
    static size_t SHA_TESTSTR_SIZE = 32;
#if !defined(TEST_STACK) && !defined(TEST_MEM)
    static uint8_t EXPECTED_RESULT_SHA256[] = {
        0x65, 0x0C, 0x3A, 0xC7, 0xF9, 0x33, 0x17, 0xD3,
        0x96, 0x31, 0xD3, 0xF5, 0xC5, 0x5B, 0x0A, 0x1E,
        0x96, 0x68, 0x04, 0xE2, 0x73, 0xC3, 0x8F, 0x93,
        0x9C, 0xB1, 0x45, 0x4D, 0xC2, 0x69, 0x7D, 0x20
    };
#endif /* TEST_STACK */
#endif /* INPUT_512 */

#ifdef BOARD_PBA_D_01_KW2X

static void sha256_test(void)
{
    uint8_t sha256_result[SHA256_DIGEST_SIZE];
    sha256_context_t ctx;
#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        sha256_init(&ctx);
        printf("Sha256 Init: %ld us\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        sha256_update(&ctx, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
        printf("Sha256 Update: %ld us\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        sha256_final(&ctx, sha256_result);
        printf("Sha256 Final: %ld us\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        sha256_init(&ctx);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        sha256_update(&ctx, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        sha256_final(&ctx, sha256_result);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */
    if (memcmp(sha256_result, EXPECTED_RESULT_SHA256, SHA256_DIGEST_SIZE)) {
        printf("SHA-256 Failure\n");

        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x ", sha256_result[i]);
        }
        printf("\n");
    }
    else {
        printf("SHA-256 Success\n");
    }
#else
    sha256_init(&ctx);
    sha256_update(&ctx, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
    sha256_final(&ctx, sha256_result);
#endif /* TEST_STACK */
}

#else

static void sha256_test(void)
{
    uint8_t sha256_result[SHA256_DIGEST_SIZE];

    hwcrypto_acquire(dev);
#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        hwcrypto_hash_init(dev, HWCRYPTO_SHA256);
        printf("Sha256 Init: %ld us\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_hash_update(dev, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
        printf("Sha256 Update: %ld us\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_hash_final(dev, sha256_result, SHA256_DIGEST_SIZE);
        printf("Sha256 Final: %ld us\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        hwcrypto_hash_init(dev, HWCRYPTO_SHA256);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_hash_update(dev, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_hash_final(dev, sha256_result, SHA256_DIGEST_SIZE);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */
    if (memcmp(sha256_result, EXPECTED_RESULT_SHA256, SHA256_DIGEST_SIZE)) {
        printf("SHA-256 Failure\n");

        for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
            printf("%02x ", sha256_result[i]);
        }
        printf("\n");
    }
    else {
        printf("SHA-256 Success\n");
    }
#else
    hwcrypto_hash_init(dev, HWCRYPTO_SHA256);
    hwcrypto_hash_update(dev, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
    hwcrypto_hash_final(dev, sha256_result, SHA256_DIGEST_SIZE);
#endif /* TEST_STACK */
    hwcrypto_release(dev);
}
#endif /* BOARD_PBA_D_01_KW2X */
#endif /* SHA256 */

#if AES
#define AES_BLOCK_SIZE      (16)
static uint8_t AES_KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static uint8_t AES_KEY_SIZE = 16;
#endif

#if AES_ECB
/* AES Test */
#ifndef INPUT_512
    static uint8_t __attribute__((aligned)) ECB_PLAIN[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    static uint8_t ECB_PLAIN_LEN = 32;

    static uint8_t __attribute__((aligned))ECB_CIPHER[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
    };
    static uint8_t ECB_CIPHER_LEN = 32;
#else
    static const unsigned char ECB_PLAIN[] = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Ste";
    static size_t ECB_PLAIN_LEN = 512;

    static uint8_t __attribute__((aligned))ECB_CIPHER[] = {
        0xbf, 0xd7, 0x5c, 0xff, 0xc4, 0x2c, 0x4d, 0xf8,
        0xc7, 0xd6, 0xfa, 0x0e, 0x71, 0x5b, 0xae, 0xdb,
        0x0f, 0x0c, 0xe6, 0xb8, 0xac, 0x10, 0x27, 0x90,
        0xbf, 0xd7, 0x80, 0x78, 0xf2, 0x6e, 0x87, 0x05,
        0x25, 0x9b, 0x53, 0x92, 0xa7, 0x2c, 0x73, 0x7c,
        0x9d, 0x90, 0x51, 0x2d, 0x02, 0x39, 0xdd, 0x7d,
        0xc3, 0x8a, 0x0d, 0xc4, 0xbe, 0x88, 0x32, 0xc0,
        0xc8, 0xac, 0xa5, 0x06, 0x41, 0x09, 0x75, 0xb7,
        0xcd, 0xc9, 0xc1, 0x5d, 0xc6, 0x6c, 0xae, 0xb6,
        0xfd, 0x44, 0x76, 0x79, 0x5a, 0x9a, 0x02, 0xe0,
        0x35, 0xbf, 0x5b, 0xb4, 0xbb, 0xe9, 0x60, 0xa8,
        0x52, 0x40, 0x01, 0xf8, 0xcc, 0x03, 0x33, 0xc9,
        0x51, 0x46, 0x12, 0xe6, 0x48, 0x35, 0x26, 0xd9,
        0x49, 0x7e, 0x07, 0xa2, 0x2f, 0xb3, 0x6a, 0x22,
        0x7b, 0x9f, 0xab, 0x81, 0xc8, 0x3f, 0x73, 0xb6,
        0x4f, 0x6d, 0xd3, 0xe3, 0x77, 0xf2, 0xdd, 0xfe,
        0x65, 0xa5, 0xb2, 0xcf, 0x5a, 0x9e, 0xa8, 0xbe,
        0x37, 0x8a, 0x2e, 0x49, 0x87, 0xf6, 0x4d, 0xf8,
        0x0b, 0x05, 0x55, 0x32, 0xac, 0x75, 0xe1, 0x70,
        0x1b, 0xee, 0x8e, 0x44, 0x8c, 0xba, 0xfe, 0xff,
        0xc4, 0x72, 0xe2, 0x1d, 0x43, 0x3d, 0x09, 0x94,
        0x35, 0x68, 0x1f, 0x53, 0xb4, 0x9e, 0x1e, 0x36,
        0x08, 0xc1, 0x6c, 0xe8, 0x05, 0x6a, 0x9b, 0xc6,
        0xc1, 0x93, 0x37, 0x1d, 0x71, 0x0f, 0x39, 0x1f,
        0xb4, 0x21, 0x5c, 0x03, 0x5b, 0x7c, 0x63, 0x30,
        0xa3, 0x75, 0x06, 0xb2, 0xbf, 0x6b, 0x6a, 0x99,
        0x65, 0xfa, 0xab, 0xd3, 0x09, 0xaf, 0x6c, 0x3e,
        0x10, 0xbe, 0x2f, 0x8d, 0xff, 0x21, 0x76, 0x40,
        0x48, 0xfe, 0x0b, 0x13, 0xc8, 0xe8, 0x8d, 0x9e,
        0xea, 0x9d, 0x41, 0xa0, 0x3f, 0xc7, 0xe2, 0xa4,
        0x8f, 0xca, 0xe0, 0xbb, 0x6f, 0x9a, 0x43, 0x2d,
        0xcd, 0xc7, 0x92, 0xf3, 0x14, 0xf7, 0x61, 0xfd,
        0x10, 0x91, 0x4c, 0x13, 0xb0, 0x89, 0x9d, 0x58,
        0x50, 0x2f, 0xf0, 0x90, 0x9a, 0xce, 0x41, 0x39,
        0x77, 0x28, 0x3c, 0x25, 0x2d, 0x43, 0x65, 0x36,
        0x05, 0x5c, 0x39, 0xfe, 0xc2, 0xcf, 0x9c, 0x81,
        0x9c, 0xe0, 0xe5, 0xa0, 0xc8, 0x87, 0x80, 0x14,
        0x65, 0x4c, 0x5d, 0xa9, 0xaf, 0x7d, 0xfb, 0x60,
        0x1e, 0xc7, 0x56, 0x83, 0xfa, 0xfd, 0x95, 0x56,
        0x2f, 0xa1, 0x7b, 0x90, 0x13, 0x8e, 0x32, 0x84,
        0xe6, 0x46, 0xc6, 0x76, 0x8f, 0x7d, 0x10, 0x53,
        0x13, 0x28, 0x0b, 0x8a, 0x4b, 0x88, 0xe7, 0x19,
        0x0b, 0x1e, 0xa1, 0x37, 0x1a, 0xef, 0x01, 0x54,
        0x69, 0x90, 0x82, 0x8d, 0x43, 0x5a, 0x5e, 0xb7,
        0xda, 0x6d, 0x5e, 0x0b, 0xcf, 0x22, 0x75, 0xb7,
        0x14, 0xa5, 0xb2, 0x80, 0x7d, 0x22, 0xba, 0x2b,
        0xe2, 0x2b, 0x8e, 0x48, 0x1c, 0xdc, 0x37, 0x9c,
        0x1c, 0xb4, 0xd3, 0xf1, 0x03, 0xeb, 0x06, 0xdf,
        0x18, 0xed, 0xbc, 0x09, 0x64, 0x11, 0x45, 0x26,
        0xb6, 0xd3, 0x59, 0x01, 0xb6, 0x82, 0xcf, 0x41,
        0xcd, 0x38, 0x1d, 0xa3, 0xb9, 0xc3, 0x1c, 0x14,
        0xa0, 0x0a, 0x7f, 0x96, 0x48, 0x90, 0x1f, 0xb5,
        0xb6, 0xbb, 0x68, 0x42, 0x63, 0x9e, 0xca, 0x09,
        0xb6, 0xf1, 0x79, 0xa5, 0x69, 0xc8, 0x5e, 0x28,
        0xc0, 0xdd, 0x69, 0xe3, 0xd9, 0x40, 0x3f, 0xf6,
        0xcf, 0xc7, 0x27, 0x93, 0x32, 0x50, 0x1d, 0x87,
        0x25, 0xad, 0xb5, 0xc8, 0x16, 0xfa, 0x47, 0x60,
        0xe7, 0x00, 0x88, 0xc6, 0x01, 0xa7, 0xa2, 0xd7,
        0x1d, 0xbd, 0xfe, 0x5f, 0xbb, 0x00, 0x42, 0xd5,
        0x31, 0xba, 0xdc, 0x59, 0x3c, 0xa4, 0xcb, 0x56,
        0x1d, 0x3c, 0xbc, 0x36, 0x9e, 0x88, 0x55, 0xca,
        0xef, 0x5b, 0xce, 0xbe, 0xd8, 0x2e, 0x32, 0x6c,
        0x11, 0x3b, 0x1d, 0xc5, 0x4e, 0x20, 0x6e, 0x48,
        0x72, 0x52, 0x07, 0xc1, 0x62, 0x09, 0x37, 0x50
        };
    #define ECB_CIPHER_LEN 512
#endif /* INPUT_512 */

#ifdef BOARD_PBA_D_01_KW2X
void aes_test_ecb(void)
{
    cipher_t ciph;
    uint8_t data[ECB_PLAIN_LEN];
    memset(data, 0, ECB_PLAIN_LEN);

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
        printf("AES ECB Init: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        cipher_encrypt_ecb(&ciph, ECB_PLAIN, ECB_PLAIN_LEN, data);
        printf("AES ECB Set Key: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        cipher_encrypt_ecb(&ciph, ECB_PLAIN, ECB_PLAIN_LEN, data);
        gpio_toggle(active_gpio);

        if (memcmp(data, ECB_CIPHER, ECB_CIPHER_LEN)) {
            printf("AES ECB encryption wrong cipher\n");
        }

    #endif /* USE_TIMER */
#else
    cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
    cipher_encrypt_ecb(&ciph, ECB_PLAIN, ECB_PLAIN_LEN, data);
#endif /* TES_STACK */

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        cipher_decrypt_ecb(&ciph, ECB_CIPHER, ECB_CIPHER_LEN, data);
        printf("AES ECB Decrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        cipher_decrypt_ecb(&ciph, ECB_CIPHER, ECB_CIPHER_LEN, data);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */

    if (memcmp(data, ECB_PLAIN, ECB_PLAIN_LEN)) {
        printf("AES ECB decryption wrong plain\n");
    }
#else
    cipher_decrypt_ecb(&ciph, ECB_CIPHER, ECB_CIPHER_LEN, data);
#endif /* TEST_STACK */
}
#else

void aes_test_ecb(void)
{
    uint8_t data[ECB_CIPHER_LEN];
    hwcrypto_acquire(dev);

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_ECB);
        printf("AES ECB Init: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
        printf("AES ECB Set Key: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_cipher_encrypt(dev, ECB_PLAIN, data, ECB_PLAIN_LEN);
        printf("AES ECB Encrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_ECB);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_cipher_encrypt(dev, ECB_PLAIN, data, ECB_PLAIN_LEN);
        gpio_toggle(active_gpio);

        if (memcmp(data, ECB_CIPHER, ECB_CIPHER_LEN)) {
            printf("AES ECB encryption wrong cipher\n");
        }

    #endif /* USE_TIMER */
#else
    hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_ECB);
    hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
    hwcrypto_cipher_encrypt(dev, ECB_PLAIN, data, ECB_PLAIN_LEN);
#endif /* TES_STACK */

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        hwcrypto_cipher_decrypt(dev, ECB_CIPHER, data, ECB_CIPHER_LEN);
        printf("AES ECB Decrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        hwcrypto_cipher_decrypt(dev, ECB_CIPHER, data, ECB_CIPHER_LEN);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */

    if (memcmp(data, ECB_PLAIN, ECB_PLAIN_LEN)) {
        printf("AES ECB decryption wrong plain\n");
    }
#else
    hwcrypto_cipher_decrypt(dev, ECB_CIPHER, data, ECB_CIPHER_LEN);
#endif /* TEST_STACK */
    hwcrypto_release(dev);
}
#endif /* BOARD_PBA_D_01_KW2X */
#endif /* AES_ECB */

#if AES_CBC
/* AES Test */
 static uint8_t CBC_IV[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
#ifndef INPUT_512
    static uint8_t __attribute__((aligned)) CBC_PLAIN[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    static uint8_t CBC_PLAIN_LEN = 32;

    static uint8_t __attribute__((aligned)) CBC_CIPHER[] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
    };
    static uint8_t CBC_CIPHER_LEN = 32;
#else
    static unsigned char CBC_PLAIN[] = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Ste";
    #define CBC_PLAIN_LEN 512

    static uint8_t __attribute__((aligned)) CBC_CIPHER[] = {
        0xfa, 0xf4, 0x41, 0xbb, 0x79, 0x4a, 0x7a, 0x3e,
        0x27, 0x4f, 0x28, 0x6d, 0x11, 0x25, 0x7b, 0xc0,
        0xb8, 0x36, 0xab, 0x12, 0x1c, 0xd3, 0x5c, 0x3f,
        0x95, 0x3a, 0x55, 0x02, 0x36, 0x00, 0x5d, 0x12,
        0x80, 0x93, 0xf5, 0x53, 0xf1, 0xa3, 0x3a, 0x7c,
        0xac, 0x2f, 0x47, 0xe6, 0x85, 0x9b, 0xcd, 0x9f,
        0xfb, 0x8e, 0x22, 0xdd, 0xb3, 0xc0, 0x4c, 0x4f,
        0x7c, 0x26, 0x2b, 0x05, 0x4b, 0x21, 0x98, 0x53,
        0x1d, 0x09, 0x42, 0x90, 0x1f, 0x51, 0x44, 0x70,
        0xa6, 0xde, 0x84, 0x45, 0x6b, 0xb6, 0x71, 0x7f,
        0xc7, 0x83, 0x7c, 0x15, 0x8f, 0x1b, 0x9e, 0x47,
        0x0a, 0x41, 0xe6, 0x6c, 0x90, 0xf9, 0x37, 0x08,
        0xa5, 0x12, 0x38, 0x34, 0x46, 0x30, 0xc8, 0x47,
        0xaa, 0x77, 0x82, 0xd7, 0xda, 0xa7, 0x31, 0xcb,
        0xdc, 0x7c, 0xae, 0x2b, 0x69, 0xa7, 0xa1, 0x7a,
        0xd2, 0x87, 0x85, 0x82, 0xcd, 0xf0, 0xb2, 0x1b,
        0x11, 0x84, 0x65, 0x0a, 0x73, 0xad, 0x63, 0xff,
        0x62, 0x64, 0xfd, 0x95, 0x83, 0x97, 0x66, 0x91,
        0xac, 0xc1, 0x4f, 0x2f, 0xfe, 0xbc, 0xd4, 0xdd,
        0xe2, 0x75, 0xbd, 0x96, 0xa9, 0xb2, 0x85, 0x8b,
        0xe2, 0xe7, 0x95, 0x98, 0x66, 0x64, 0x1f, 0x75,
        0x07, 0x39, 0x56, 0x7f, 0x31, 0xc2, 0xe6, 0x6e,
        0x9b, 0xf0, 0xf9, 0x24, 0xc0, 0xae, 0x98, 0x19,
        0x71, 0x35, 0x81, 0x85, 0xf9, 0x1f, 0x50, 0xc1,
        0x9c, 0x83, 0xac, 0x95, 0x19, 0x9f, 0x4c, 0x65,
        0x93, 0x67, 0x7d, 0x04, 0xf1, 0x73, 0x89, 0x06,
        0xeb, 0xf3, 0xf2, 0x15, 0xc7, 0xf0, 0xf1, 0xcc,
        0x96, 0xed, 0x09, 0xa2, 0xaf, 0x36, 0x5d, 0x5b,
        0x9f, 0x8b, 0xb2, 0x4e, 0x0d, 0x7d, 0x4c, 0x19,
        0xcd, 0x36, 0xaf, 0x45, 0xfd, 0x3f, 0x03, 0xca,
        0x96, 0x15, 0x79, 0xd0, 0x6a, 0x8c, 0x2b, 0xc8,
        0xb1, 0x45, 0x49, 0x8f, 0x96, 0xa0, 0x2c, 0xa2,
        0x04, 0xa2, 0x98, 0xa3, 0xa0, 0xce, 0x15, 0x00,
        0x64, 0xeb, 0x81, 0x9f, 0xdb, 0xd8, 0x28, 0x83,
        0xc4, 0x1b, 0x83, 0x77, 0x59, 0x7d, 0x5f, 0x33,
        0x23, 0x95, 0x29, 0x8b, 0x3a, 0x1f, 0xff, 0x5a,
        0x4d, 0xe3, 0x6f, 0xd4, 0x99, 0xbe, 0x7a, 0x6b,
        0x3d, 0x6c, 0x5b, 0x3e, 0x2a, 0xd0, 0x8a, 0x50,
        0x65, 0xd1, 0xba, 0xcc, 0xa9, 0x17, 0xcd, 0xbd,
        0xb7, 0xd3, 0xf2, 0x39, 0x20, 0xb2, 0x3e, 0xb3,
        0x69, 0x08, 0x80, 0xdd, 0x81, 0x01, 0xad, 0xb3,
        0xd5, 0x34, 0x2a, 0x99, 0x8c, 0x33, 0x9a, 0xf9,
        0x37, 0xd6, 0x4b, 0x39, 0x9e, 0xc0, 0x77, 0x9a,
        0x20, 0xf3, 0xd0, 0x98, 0xdc, 0x35, 0x18, 0xde,
        0x04, 0xa5, 0x70, 0x59, 0x2f, 0x5b, 0xca, 0x94,
        0x76, 0x8e, 0xb8, 0x03, 0x4b, 0x90, 0x69, 0x5f,
        0x70, 0x94, 0xe7, 0x05, 0x7b, 0x09, 0xbc, 0x3c,
        0x4b, 0x14, 0xa1, 0x87, 0x82, 0x42, 0xaa, 0x2c,
        0x24, 0xe3, 0xaf, 0x19, 0x3d, 0x50, 0xfa, 0xff,
        0xd2, 0x98, 0xef, 0xa3, 0x5b, 0x37, 0x9b, 0xda,
        0x07, 0x7b, 0x04, 0x5c, 0xb2, 0x47, 0x9d, 0x42,
        0xc1, 0xc5, 0xdf, 0x75, 0xec, 0x38, 0x74, 0x3e,
        0xaf, 0xf4, 0x30, 0x90, 0x1b, 0x1a, 0x45, 0x82,
        0x7d, 0x7e, 0xf8, 0x22, 0x4d, 0x3e, 0xac, 0x37,
        0x03, 0x10, 0x29, 0x50, 0x29, 0x68, 0x70, 0xf9,
        0xd1, 0xd6, 0x35, 0xd7, 0xdc, 0x1d, 0x52, 0x08,
        0x72, 0x51, 0x61, 0x94, 0x96, 0x56, 0xa6, 0xfd,
        0x63, 0xaa, 0x99, 0x08, 0xc1, 0xd7, 0x37, 0x73,
        0x0f, 0x9d, 0xa6, 0x7e, 0xe5, 0x9e, 0x53, 0x21,
        0xa2, 0x89, 0xd0, 0x4b, 0x33, 0xf9, 0x9f, 0x6a,
        0x02, 0x47, 0x41, 0x95, 0x83, 0x8c, 0x15, 0x5a,
        0xcb, 0x80, 0xad, 0x5b, 0x1a, 0x5f, 0xbe, 0xc9,
        0xca, 0xd2, 0xd5, 0xdf, 0x5d, 0x7f, 0x56, 0x76,
        0xfd, 0x74, 0x39, 0x94, 0x70, 0x28, 0x85, 0x1c
    };
    #define CBC_CIPHER_LEN 512
#endif /* INPUT_512 */

#ifdef BOARD_PBA_D_01_KW2X
void aes_test_cbc(void)
{
    cipher_t ciph;
    uint8_t data[CBC_PLAIN_LEN];
    memset(data, 0, CBC_PLAIN_LEN);

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
        printf("AES CBC Init: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        cipher_encrypt_cbc(&ciph, CBC_IV, CBC_PLAIN, CBC_PLAIN_LEN, data);
        printf("AES CBC Set Key: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        cipher_encrypt_cbc(&ciph, CBC_IV, CBC_PLAIN, CBC_PLAIN_LEN, data);
        gpio_toggle(active_gpio);

        if (memcmp(data, CBC_CIPHER, CBC_CIPHER_LEN)) {
            printf("AES CBC encryption wrong cipher\n");
        }

    #endif /* USE_TIMER */
#else
    cipher_init(&ciph, CIPHER_AES_128, AES_KEY, AES_KEY_SIZE);
    cipher_encrypt_cbc(&ciph, CBC_IV, CBC_PLAIN, CBC_PLAIN_LEN, data);
#endif /* TES_STACK */

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        cipher_decrypt_cbc(&ciph, CBC_IV, CBC_CIPHER, CBC_CIPHER_LEN, data);
        printf("AES CBC Decrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        cipher_decrypt_cbc(&ciph, CBC_IV, CBC_CIPHER, CBC_CIPHER_LEN, data);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */

    if (memcmp(data, CBC_PLAIN, CBC_PLAIN_LEN)) {
        printf("AES CBC decryption wrong plain\n");
    }
#else
    cipher_decrypt_cbc(&ciph, CBC_IV, CBC_CIPHER, CBC_CIPHER_LEN, data);
#endif /* TEST_STACK */
}
#else

void aes_test_cbc(void)
{
    uint8_t data[CBC_CIPHER_LEN];
    hwcrypto_acquire(dev);

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_CBC);
        printf("AES CBC Init: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
        printf("AES CBC Set Key: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_IV, CBC_IV, 16);
        printf("AES CBC Set IV: %ld\n", xtimer_now_usec()-start);

        start = xtimer_now_usec();
        hwcrypto_cipher_encrypt(dev, CBC_PLAIN, data, CBC_PLAIN_LEN);
        printf("AES CBC Encrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_CBC);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_cipher_set(dev, HWCRYPTO_OPT_IV, CBC_IV, 16);
        gpio_toggle(active_gpio);

        gpio_toggle(active_gpio);
        hwcrypto_cipher_encrypt(dev, CBC_PLAIN, data, CBC_PLAIN_LEN);
        gpio_toggle(active_gpio);

        if (memcmp(data, CBC_CIPHER, CBC_CIPHER_LEN)) {
            printf("AES CBC encryption wrong cipher\n");
        }

    #endif /* USE_TIMER */
#else
    hwcrypto_cipher_init(dev, HWCRYPTO_AES128, HWCRYPTO_MODE_CBC);
    hwcrypto_cipher_set(dev, HWCRYPTO_OPT_KEY, AES_KEY, AES_KEY_SIZE);
    hwcrypto_cipher_set(dev, HWCRYPTO_OPT_IV, CBC_IV, 16);
    hwcrypto_cipher_encrypt(dev, CBC_PLAIN, data, CBC_PLAIN_LEN);
#endif /* TES_STACK */

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    #if USE_TIMER
        start = xtimer_now_usec();
        hwcrypto_cipher_decrypt(dev, CBC_CIPHER, data, CBC_CIPHER_LEN);
        printf("AES CBC Decrypt: %ld\n", xtimer_now_usec()-start);
    #else
        gpio_toggle(active_gpio);
        hwcrypto_cipher_decrypt(dev, CBC_CIPHER, data, CBC_CIPHER_LEN);
        gpio_toggle(active_gpio);
    #endif /* USE_TIMER */
    if (memcmp(data, CBC_PLAIN, CBC_PLAIN_LEN)) {
        printf("AES CBC decryption wrong plain\n");
    }
#else
    hwcrypto_cipher_decrypt(dev, CBC_CIPHER, data, CBC_CIPHER_LEN);
#endif /* TEST_STACK */
    hwcrypto_release(dev);
}
#endif /* BOARD_PBA_XXX */
#endif /* AES_CBC */

int main(void)
{
#if !defined(TEST_STACK) && !defined(TEST_MEM)
    puts("HWCRYPTO PR test start");
    gpio_init(active_gpio, GPIO_OUT);
    gpio_init(acq_rel_gpio, GPIO_OUT);
    gpio_clear(active_gpio);
    gpio_clear(acq_rel_gpio);
#endif

#ifdef BOARD_SLSTK3402A
    hwcrypto_init(dev);
#endif
#if SHA256
    puts("HWCRYPTO PR SHA256 Start");
    sha256_test();
#endif
#if AES_ECB
    puts("HWCRYPTO PR AES ECB Start");
    aes_test_ecb();
#endif
#if AES_CBC
    puts("HWCRYPTO PR AES CBC Start");
    aes_test_cbc();
#endif

#if TEST_STACK
    ps();
#endif

#if !defined(TEST_STACK) && !defined(TEST_MEM)
    puts("Done");
#endif
    return 0;
}
