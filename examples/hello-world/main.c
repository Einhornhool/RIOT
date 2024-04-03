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
#include "psa/crypto.h"
#include "psa/client.h"

// #include "clk.h"
// #include "board.h"
// #include "periph_conf.h"
// #include "timex.h"
// #include "ztimer.h"

#define ECDSA_MESSAGE_SIZE  (127)
#define ECC_KEY_SIZE    (256)

const uint8_t hash_input[32] = { 0x88 };

psa_status_t example_ecdsa_p256(void)
{
    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;
    uint8_t bytes =
        PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), bits);

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(
                                                             PSA_ECC_FAMILY_SECP_R1),
                                                         ECC_KEY_SIZE)] = { 0 };
    size_t pubkey_length;
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

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature),
                           &sig_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
}

int main(void)
{
    puts("Hello World!");

    printf("You are running RIOT on a %s board.\n", RIOT_BOARD);
    printf("This board features a %s MCU.\n", RIOT_MCU);

    uint32_t fw_version = psa_framework_version();
    printf("FW  version = %ld\r\n", fw_version);

    uint8_t number;
    printf("Testing psa get random number...\r\n");
    for (int i = 0; i < 5; i++) {
        if (psa_generate_random(&number, sizeof(number)) == PSA_SUCCESS) {
            printf("%d: psa_generate_random() = %d\r\n", i, number);
        }
    }
    uint8_t hash_output[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_size = 0;

    psa_status_t status = psa_crypto_init();
    status = psa_hash_compute(PSA_ALG_SHA_256, hash_input, sizeof(hash_input), hash_output, sizeof(hash_output), &hash_size);
    if (status == PSA_SUCCESS) {
        printf("Hash success\n");
    }
    else {
        printf("Hash failed: %d\n", (int)status);
    }

    status = example_ecdsa_p256();
    if (status != PSA_SUCCESS) {
        printf("ECDSA failed with status: %d\n", (int) status);
    }
    printf("Status: %d\n", (int) status);
    puts("Done");

    return 0;
}
