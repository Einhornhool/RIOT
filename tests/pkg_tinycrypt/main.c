/*
 * Copyright (C) 2018 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Test the correct loading and linking of the tinycrypt package
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "fmt.h"
#include "tinycrypt/aes.h"

#include "xtimer.h"

uint32_t start, stop, t_diff;

static void dump_block(const char *head, const uint8_t *block)
{
    printf("%s [", head);
    for (unsigned i = 0; i < TC_AES_BLOCK_SIZE; i++) {
        char tmp[3] = { 0 };
        fmt_byte_hex(tmp, block[i]);
        printf(" 0x%s", tmp);
    }
    printf(" ]\n");
}

int main(void)
{
    puts("Tinycrypt AES128 test\n");

    struct tc_aes_key_sched_struct s;

    /* 128-bit key to use */
    const char *key = "That's my Kung Fu";
    /* one block (TC_AES_BLOCK_SIZE := 16 byte) of plain text */
    const char *plain = "Two One Nine Two";
    /* some memory to store the encrypted data (add '\0` termination)*/
    uint8_t cipher[TC_AES_BLOCK_SIZE + 1];
    uint8_t result[TC_AES_BLOCK_SIZE + 1];
    memset(cipher, 0, TC_AES_BLOCK_SIZE + 1);
    memset(result, 0, TC_AES_BLOCK_SIZE + 1);

    /* initialize key */
    puts("128-bit key used for this test:");
    printf("key (ASCII): '%s'\n", key);
    dump_block("      key:", (const uint8_t *)key);
    start = xtimer_now_usec();
    tc_aes128_set_encrypt_key(&s, (const uint8_t *)key);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("TC set encrypt key: %ld us\n", t_diff);
    puts("\nData to encrypt (1 block of 16 bytes):");
    printf(" plain text: '%s'\n", plain);
    dump_block("      hex:", (const uint8_t *)plain);

    puts("\nCipher and result before encryption:");
    dump_block("   cypher:", cipher);

    /* encrypt data */

    start = xtimer_now_usec();
    tc_aes_encrypt(cipher, (const uint8_t *)plain, &s);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("TC encrypt: %ld us\n", t_diff);

    puts("\nEncrypted data:");
    dump_block("encrypted:", cipher);

    /* decrypt data again */
    start = xtimer_now_usec();
    tc_aes128_set_decrypt_key(&s, (const uint8_t *)key);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("TC set decrypt key: %ld us\n", t_diff);

    start = xtimer_now_usec();
    tc_aes_decrypt(result, cipher, &s);
    stop = xtimer_now_usec();
    t_diff = stop - start;
    printf("TC decrypt: %ld us\n", t_diff);

    puts("\nAnd now decrypt the cipher again:");
    dump_block("decrypted:", result);
    printf("    ASCII: %s\n\n", (const char *)result);

    /* test results */
    if (memcmp(plain, result, TC_AES_BLOCK_SIZE) != 0) {
        puts("[FAILED]");
    }
    else {
        puts("[SUCCESS]");
    }

    return 0;
}
