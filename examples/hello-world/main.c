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
#include "hashes/sha1.h"
#include "hashes/sha256.h"
#include "crypto/aes.h"
#include "crypto/ciphers.h"

#include "vendor/nrf52840.h"
#include "nrf-sdk/external/nrf_cc310/include/sns_silib.h"
#include "nrf-sdk/external/nrf_cc310/include/crys_hash.h"
#include "ssi_aes.h"

uint8_t sha1_result[SHA1_DIGEST_LENGTH];
uint8_t sha256_result[SHA256_DIGEST_LENGTH];
char teststring[] = "Lorem ipsum dolor sit amet";
uint8_t expected_result_sha1[] = { 0x38, 0xf0, 0x0f, 0x87, 0x38, 0xe2, 0x41, 0xda, 0xea, 0x6f, 0x37, 0xf6, 0xf5, 0x5a, 0xe8, 0x41, 0x4d, 0x7b, 0x02, 0x19 };

uint8_t expected_result_sha256[] = { 0x16, 0xAB, 0xA5, 0x39, 0x3A, 0xD7, 0x2C, 0x00, 0x41, 0xF5, 0x60, 0x0A, 0xD3, 0xC2, 0xC5, 0x2E, 0xC4, 0x37, 0xA2, 0xF0, 0xC7, 0xFC, 0x08, 0xFA, 0xDF, 0xC3, 0xC0, 0xFE, 0x96, 0x41, 0xD7, 0xA3 };

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

/*---------- Board initialization stuff -----------*/
extern void CRYPTOCELL_IRQHandler(void);
void isr_cryptocell(void)
{
    CRYPTOCELL_IRQHandler();
}

CRYS_RND_WorkBuff_t*  rndWorkBuff_ptr;
CRYS_RND_State_t*     rndState_ptr;

#if defined(__CC_ARM)
CRYS_RND_State_t   	 rndState = {0};
CRYS_RND_WorkBuff_t  rndWorkBuff = {0};
#else
CRYS_RND_State_t   	 rndState;
CRYS_RND_WorkBuff_t  rndWorkBuff;
#endif

static void cryptocell_setup(void)
{
    int ret = 0;
    rndState_ptr = &rndState;
    rndWorkBuff_ptr = &rndWorkBuff;

    NVIC_EnableIRQ(CRYPTOCELL_IRQn);

    NRF_CRYPTOCELL->ENABLE = 1;

    ret = SaSi_LibInit();
    if (ret != SA_SILIB_RET_OK) {
        printf("SaSi_LibInit failed: 0x%x\n", ret);
    }

    ret = CRYS_RndInit(rndState_ptr, rndWorkBuff_ptr);
    if (ret != SA_SILIB_RET_OK) {
        printf("CRYS_RndInit failed: 0x%x\n", ret);
    }
}

/*----------- Test functions ------------*/

/* For more examples download the nrf sdk here:
https://www.nordicsemi.com/Software-and-Tools/Software/nRF5-SDK

and take a look at the examples folder */

static void cryptocell_sha1(void)
{
    int ret = 0;
    uint32_t digest[SHA1_DIGEST_LENGTH];
    CRYS_HASHUserContext_t ctx;

    ret = CRYS_HASH_Init(&ctx, CRYS_HASH_SHA1_mode);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Init failed: 0x%x\n", ret);
    }

    ret = CRYS_HASH_Update(&ctx, (uint8_t*)teststring, teststring_size);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Update failed: 0x%x\n", ret);
    }

    ret = CRYS_HASH_Finish(&ctx, digest);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA1: CRYS_HASH_Finish failed: 0x%x\n", ret);
    }

    if (memcmp((uint8_t*)digest, expected_result_sha1, SHA1_DIGEST_LENGTH) != 0) {
        printf("CRYS_HASH SHA1 Failure\n");

        for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
            printf("%02lx ", digest[i]);
        }
        printf("\n");
    }
    else {
        printf("CRYS_HASH SHA1 Success\n");
    }
}

static void cryptocell_sha256(void)
{
    int ret = 0;
    uint32_t digest[SHA256_DIGEST_LENGTH];
    CRYS_HASHUserContext_t ctx;

    ret = CRYS_HASH_Init(&ctx, CRYS_HASH_SHA256_mode);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA256: CRYS_HASH_Init failed: 0x%x\n", ret);
    }

    ret = CRYS_HASH_Update(&ctx, (uint8_t*)teststring, teststring_size);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA256: CRYS_HASH_Update failed: 0x%x\n", ret);
    }

    ret = CRYS_HASH_Finish(&ctx, digest);
    if (ret != SA_SILIB_RET_OK) {
        printf("SHA256: CRYS_HASH_Finish failed: 0x%x\n", ret);
    }

    if (memcmp((uint8_t*)digest, expected_result_sha256, SHA256_DIGEST_LENGTH) != 0) {
        printf("CRYS_HASH SHA256 Failure\n");

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02lx ", digest[i]);
        }
        printf("\n");
    }
    else {
        printf("CRYS_HASH SHA256 Success\n");
    }
}

static void cryptocell_aes(void)
{
    SaSiAesUserContext_t enc, dec;
    SaSiAesUserKeyData_t key;
    uint8_t data[AES_BLOCK_SIZE];
    size_t data_size = 16;
    int ret = 0;

    // memcpy(&key.pKey, TEST_0_KEY, AES_KEY_SIZE);
    key.pKey = TEST_0_KEY;
    key.keySize = AES_KEY_SIZE;

    ret = SaSi_AesInit(&enc, SASI_AES_ENCRYPT, SASI_AES_MODE_ECB,SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesInit enc failed: 0x%x\n", ret);
    }

    ret = SaSi_AesInit(&dec, SASI_AES_DECRYPT, SASI_AES_MODE_ECB,SASI_AES_PADDING_NONE);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesInit dec failed: 0x%x\n", ret);
    }

    ret = SaSi_AesSetKey(&enc, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesSetKey enc failed: 0x%x\n", ret);
    }

    ret = SaSi_AesSetKey(&dec, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesSetKey dec failed: 0x%x\n", ret);
    }

    ret = SaSi_AesFinish(&enc, data_size, TEST_0_INP, data_size, data, &data_size);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesFinish enc failed: 0x%x\n", ret);
    }

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

    ret = SaSi_AesFinish(&dec, data_size, TEST_0_ENC, data_size, data, &data_size);
    if (ret != SA_SILIB_RET_OK) {
        printf("AES: SaSi_AesFinish dec failed: 0x%x\n", ret);
    }

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
int main(void)
{
    puts("Hello World!");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s MCU.\n", RIOT_MCU);

    cryptocell_setup();

    cryptocell_sha1();
    cryptocell_sha256();
    cryptocell_aes();

    return 0;
}
