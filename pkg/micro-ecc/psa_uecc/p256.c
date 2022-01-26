#include "psa/crypto.h"
#include "uECC.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

psa_status_t psa_generate_ecc_p256r1_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t * priv_key_buffer, uint8_t * pub_key_buffer,
                                                size_t *priv_key_buffer_length, size_t *pub_key_buffer_length)
{
    int ret = 0;
    struct uECC_Curve_t *curve = (struct uECC_Curve_t *) uECC_secp256r1();
    DEBUG("Micro ECC GenKey\n");

    ret = uECC_make_key(&pub_key_buffer[1], priv_key_buffer, curve);
    if (!ret) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    pub_key_buffer[0] = 0x04;
    *pub_key_buffer_length = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(attributes->type, attributes->bits);

    return PSA_SUCCESS;
}

psa_status_t psa_ecc_p256r1_export_public_key ( const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                uint8_t * data,
                                                size_t data_size,
                                                size_t * data_length)
{
    int ret = 0;
    struct uECC_Curve_t *curve = (struct uECC_Curve_t *) uECC_secp256r1();
    DEBUG("Micro ECC Export Public Key\n");
    ret = uECC_compute_public_key(key_buffer, data, curve);
    if (!ret) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *data_length = data_size;
    return PSA_SUCCESS;
}

psa_status_t psa_ecc_p256r1_sign_hash(  const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        uint8_t * signature, size_t signature_size,
                                        size_t * signature_length)
{
    int ret = 0;
    struct uECC_Curve_t *curve = (struct uECC_Curve_t *) uECC_secp256r1();
    DEBUG("Micro ECC Sign Hash\n");

    ret = uECC_sign(key_buffer, hash, hash_length, signature, curve);
    if (!ret) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *signature_length = signature_size;

    (void) alg;
    (void) attributes;
    (void) key_buffer_size;
    return PSA_SUCCESS;
}

psa_status_t psa_ecc_p256r1_verify_hash(const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        const uint8_t *signature, size_t signature_length)
{
    int ret = 0;
    struct uECC_Curve_t *curve = (struct uECC_Curve_t *) uECC_secp256r1();
    DEBUG("Micro ECC Verify Hash\n");
    DEBUG("Key Buffer Size: %d\n", key_buffer_size);
    DEBUG("Key: %d %d %d %d\n", key_buffer[0], key_buffer[1], key_buffer[2], key_buffer[3]);

    ret = uECC_verify(&key_buffer[1], hash, hash_length, signature, curve);
    if (!ret) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    (void) alg;
    (void) attributes;
    (void) key_buffer_size;
    (void) signature_length;
    return PSA_SUCCESS;
}