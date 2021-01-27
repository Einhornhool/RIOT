#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "atca_params.h"

#define ECDSA_MESSAGE_SIZE  (127)

psa_key_id_t key_id;

psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);
psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
psa_key_bits_t bits = PSA_VENDOR_ECC_MAX_CURVE_BITS;

static void ecdsa_prim_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_key_attributes_t key_attr = psa_key_attributes_init();

    /* Set key attributes */
    psa_set_key_lifetime(&key_attr, lifetime);
    psa_set_key_algorithm(&key_attr, alg);
    psa_set_key_usage_flags(&key_attr, usage);
    psa_set_key_type(&key_attr, type);
    psa_set_key_bits(&key_attr, bits);

    /* Generate a key pair. This stores both the reference to the private key and the public key
    in the same key slot and returns the key identifier which can be used to access those keys */
    status = psa_generate_key(&key_attr, &key_id);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Generate Key failed: %ld\n", status);
        return;
    }

    /* The message must be hashed before performing the signature (the psa_sign_message funtion is
    not implemented, yet, so we have to do this manually). */
    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    /* Perform sign and verify operations using the same key identifier. Psa_sign_hash uses the private key stored on the SE. Psa_verify_hash uses the public key stored locally. */
    status = psa_sign_hash(key_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(key_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Primary SE Success");
}

#ifdef MULTIPLE_BACKENDS
static void ecdsa_sec_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV1);

    /* Export public key from the stored key pair. This does not recalculate the public key, but uses the one that got stored locally after generating the key pair in the step before.*/
    status = psa_export_public_key(key_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Export Public Key failed: %ld\n", status);
        return;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    /* Set attributes for public key import */
    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, 512);
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    /* Import the previously exported public key to a slot on a secure element. The reference to the public key will be stored with a separate key identifier. */
    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    /* Perform the ECDSA operation. Psa_sign_hash uses the private key stored on the SE. Psa_verify_hash uses the public key stored on the SE */
    status = psa_sign_hash(key_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Secondary SE Success");
}
#endif

int main(void)
{
    psa_crypto_init();
    ecdsa_prim_se();
#ifdef MULTIPLE_BACKENDS
    ecdsa_sec_se();
#endif
    return 0;
}