/*
 * Copyright (C) 2022 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @brief       Example application for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "psa/crypto.h"

#if IS_USED(MODULE_PSA_MBEDTLS)
#include "mbedtls/platform.h"

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
static const uint8_t random_bytes[]
    = { 0xde, 0xa5, 0xe4, 0x5d, 0x0e, 0xa3, 0x7f, 0xc5, 0xf3, 0x66, 0x23,
        0x2a, 0x50, 0x8f, 0x4a, 0xd2, 0x0e, 0xa1, 0x3d, 0x47, 0xe4, 0xbf,
        0x5f, 0xa4, 0xd5, 0x4a, 0x57, 0xa0, 0xba, 0x01, 0x20, 0x42, 0x08,
        0x70, 0x97, 0x49, 0x6e, 0xfc, 0x58, 0x3f, 0xed, 0x8b, 0x24, 0xa5,
        0xb9, 0xbe, 0x9a, 0x51, 0xde, 0x06, 0x3f, 0x5a, 0x00, 0xa8, 0xb6,
        0x98, 0xa1, 0x6f, 0xd7, 0xf2, 0x9b, 0x54, 0x85 };

/** The type of the context passed to mbedtls_psa_external_get_random().
 *
 * Mbed TLS initializes the context to all-bits-zero before calling
 * mbedtls_psa_external_get_random() for the first time.
 *
 * The definition of this type in the Mbed TLS source code is for
 * demonstration purposes. Implementers of mbedtls_psa_external_get_random()
 * are expected to replace it with a custom definition.
 */
typedef struct {
    uintptr_t opaque[2];
} mbedtls_psa_external_random_context_t;

int mbedtls_fake_random(void *rng_state, unsigned char *output, size_t len)
{
    (void)rng_state;
    size_t i;

    /* Requesting more random data than available. */
    if (len > sizeof(random_bytes))
    {
        return 1;
    }

    for (i = 0; i < len; ++i)
    {
        output[i] = random_bytes[i % sizeof(random_bytes)];
    }

    return 0;
}

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length )
{
    (void) context;

    /* This implementation is for test purposes only!
     * Use the libc non-cryptographic random generator. */
    mbedtls_fake_random( NULL, output, output_size );
    *output_length = output_size;
    return( PSA_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG */

#ifdef MBEDTLS_PLATFORM_MEMORY
unsigned int mem_count = 0;
unsigned int mem_max = 0;

void* MyCalloc(size_t n, size_t size)
{
    void* p = NULL;
    unsigned int* p32;

    unsigned int tot_size = (n*size);

    // printf("n %d size %d tot_size %d\n",n,size,tot_size);
    p32 = malloc(tot_size + (sizeof(unsigned int) * 4));

    if(p32 == NULL)
       return NULL;

    memset(p32, 0, tot_size + (sizeof(unsigned int) * 4));

    if(p32 != NULL){
        p32[0] = (unsigned int) tot_size;
        p = (void*)(p32 + 4);

        mem_count += tot_size;
        if(mem_count > mem_max){
            mem_max = mem_count;
        }
    }

    // printf("Alloc: %p -> %u COUNT %d MAX IS: %d\n", p, (unsigned int) tot_size , mem_count,mem_max);

    return p;
}

void MyFree(void* ptr)
{
    unsigned int* p32 = (unsigned int*)ptr;

    if (ptr != NULL) {
        p32 -= 4;

        mem_count -= p32[0];
        if(mem_count > mem_max){
            mem_max = mem_count;
        }

        // printf("Free: %p -> %u COUNT %d MAX %d\n", ptr, p32[0], mem_count, mem_max);
        free(p32);
    }

}
#endif /* MBEDTLS_PLATFORM_MEMORY */
#endif

extern void cipher_aes_128(void);
extern void psa_hmac_sha256(void);
extern void ecdsa(void);
// extern void aead_aes_128();

#ifdef MULTIPLE_SE
extern void cipher_aes_128_sec_se(void);
extern void hmac_sha256_sec_se(void);
extern void ecdsa_sec_se(void);
#endif /* MULTIPLE_SE */

int main(void)
{
#ifdef MBEDTLS_PLATFORM_MEMORY
    mbedtls_platform_set_calloc_free(MyCalloc,MyFree);
#endif

    psa_crypto_init();

    psa_hmac_sha256();
    cipher_aes_128();
    ecdsa();
    // aead_aes_128();

#ifdef MULTIPLE_SE
    cipher_aes_128_sec_se();
    hmac_sha256_sec_se();
    ecdsa_sec_se();
#endif /* MULTIPLE_SE */

    puts("All Done");
    return 0;
}
