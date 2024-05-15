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
#include <string.h>
#include "psa/crypto.h"
#include "kernel_defines.h"

// #if defined(TEST_TIME)
#include "periph/gpio.h"
#include "ztimer.h"

gpio_t active_gpio = GPIO_PIN(1, 7);
gpio_t inner_gpio = GPIO_PIN(1, 6);
// #endif

#if IS_ACTIVE(MODULE_TRUSTED_FIRMWARE_M)
#include "psa/client.h"
#endif

#if defined(TEST_ECDSA)
#define ECDSA_MESSAGE_SIZE  (127)
#define ECC_KEY_SIZE    (256)

psa_status_t example_ecdsa_p256(void)
{
#if IS_USED(MODULE_MBEDTLS)
    mbedtls_svc_key_id_t key_id;
#else
    psa_key_id_t key_id;
#endif
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    gpio_set(active_gpio);
    status = psa_generate_key(&privkey_attr, &key_id);
    gpio_clear(active_gpio);
    if (status != PSA_SUCCESS) {
        return status;
    }

    gpio_set(active_gpio);
    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    gpio_clear(active_gpio);
    if (status != PSA_SUCCESS) {
        return status;
    }

    gpio_set(active_gpio);
    status = psa_sign_hash(key_id, alg, hash, sizeof(hash), signature, sizeof(signature),
                           &sig_length);
    gpio_clear(active_gpio);
    if (status != PSA_SUCCESS) {
        return status;
    }

    gpio_set(active_gpio);
    status = psa_verify_hash(key_id, alg, hash, sizeof(hash), signature, sig_length);
    gpio_clear(active_gpio);

    status = psa_destroy_key(key_id);

    return status;
}
#endif

#if TEST_ECDH
#define ECC_KEY_SIZE    (256)
psa_status_t example_ecdh_p256(void)
{
#if IS_USED(MODULE_MBEDTLS)
    mbedtls_svc_key_id_t key_id_01;
    mbedtls_svc_key_id_t key_id_02;
#else
    psa_key_id_t key_id_01;
    psa_key_id_t key_id_02;
#endif
    psa_key_attributes_t key_01 = psa_key_attributes_init();
    psa_key_attributes_t key_02 = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_VERIFY_DERIVATION | PSA_KEY_USAGE_EXPORT;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDH;
    psa_key_bits_t bits = ECC_KEY_SIZE;

    uint8_t secret_01[PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits)];
    uint8_t secret_02[PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(type, bits)];
    uint8_t pubkey_01[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(type, bits)];
    uint8_t pubkey_02[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(type, bits)];
    size_t pubkey_len_01;
    size_t pubkey_len_02;
    size_t secret_len_01;
    size_t secret_len_02;

    psa_set_key_algorithm(&key_01, alg);
    psa_set_key_usage_flags(&key_01, usage);
    psa_set_key_type(&key_01, type);
    psa_set_key_bits(&key_01, bits);

    psa_set_key_algorithm(&key_02, alg);
    psa_set_key_usage_flags(&key_02, usage);
    psa_set_key_type(&key_02, type);
    psa_set_key_bits(&key_02, bits);

    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    gpio_set(active_gpio);
    status = psa_generate_key(&key_01, &key_id_01);
    gpio_clear(active_gpio);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_generate_key(&key_02, &key_id_02);
    if (status != PSA_SUCCESS) {
        return status;
    }

    gpio_set(active_gpio);
    status = psa_export_public_key(key_id_01, pubkey_01, sizeof(pubkey_01), &pubkey_len_01);
    gpio_clear(active_gpio);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_export_public_key(key_id_02, pubkey_02, sizeof(pubkey_02), &pubkey_len_02);
        if (status != PSA_SUCCESS) {
            return status;
    }

    for (int i = 0; i < ITERATIONS; i++) {
        gpio_set(active_gpio);
        status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                    key_id_01,
                                    pubkey_02,
                                    pubkey_len_02,
                                    secret_01,
                                    sizeof(secret_01),
                                    &secret_len_01);
        gpio_clear(active_gpio);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   key_id_02,
                                   pubkey_01,
                                   pubkey_len_01,
                                   secret_02,
                                   sizeof(secret_02),
                                   &secret_len_02);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (memcmp(secret_01, secret_02, sizeof(secret_01))) {
        puts("Secrets not identical\n");
    }

    status = psa_destroy_key(key_id_01);
    status = psa_destroy_key(key_id_02);

    return status;
}
#endif

int main(void)
{
    gpio_init(active_gpio, GPIO_OUT);
    gpio_init(inner_gpio, GPIO_OUT);
    gpio_clear(active_gpio);
    gpio_clear(inner_gpio);

    ztimer_sleep(ZTIMER_SEC, 5);

    gpio_set(active_gpio);
    psa_status_t status = psa_crypto_init();
    gpio_clear(active_gpio);

    if (status != PSA_SUCCESS) {
        printf("PSA Crypto Init failed: %d\n", (int) status);
    }

    // for (int i = 0; i < ITERATIONS; i++) {
#if defined(TEST_RANDOM)
    uint8_t number;
    // printf("Testing psa get random number...\r\n");
    // for (int i = 0; i < 5; i++) {
    gpio_set(active_gpio);
    status = psa_generate_random(&number, sizeof(number));
    gpio_clear(active_gpio);

    if (status == PSA_SUCCESS) {
        // printf("%d: psa_generate_random() = %d\r\n", i, number);
    }
    else {
        printf("Random failed, result: %d\n", (int)status);
    }
#endif

#if defined(TEST_HASH)
    const uint8_t hash_input[32] = { 0x88 };
    uint8_t hash_output[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_size = 0;

    gpio_set(active_gpio);
    status = psa_hash_compute(PSA_ALG_SHA_256, hash_input, sizeof(hash_input), hash_output, sizeof(hash_output), &hash_size);
    gpio_clear(active_gpio);

    if (status == PSA_SUCCESS) {
        // printf("Hash success\n");
    }
    else {
        printf("Hash failed: %d\n", (int)status);
    }
#endif

#if defined(TEST_ECDSA)
    status = example_ecdsa_p256();
    if (status != PSA_SUCCESS) {
        printf("ECDSA failed with status: %d\n", (int) status);
    }
#endif

#if defined(TEST_ECDH)
    status = example_ecdh_p256();
    if (status != PSA_SUCCESS) {
        printf("ECDH failed with status: %d\n", (int) status);
    }
#endif
    // }
    puts("Done");

    return 0;
}
