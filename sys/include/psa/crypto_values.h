/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Value definitions for PSA Crypto.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_VALUES_H
#define PSA_CRYPTO_VALUES_H

#include "crypto_types.h"

/**
 * @brief Vendor-defined algorithm flag.
 *
 * Algorithms defined by this standard will never have the #PSA_ALG_VENDOR_FLAG
 * bit set. Vendors who define additional algorithms must use an encoding with
 * the #PSA_ALG_VENDOR_FLAG bit set and should respect the bitwise structure
 * used by standard encodings whenever practical.
 */
#define PSA_ALG_VENDOR_FLAG                     ((psa_algorithm_t)0x80000000)

#define PSA_ALG_CATEGORY_MASK                   ((psa_algorithm_t)0x7f000000)
#define PSA_ALG_CATEGORY_HASH                   ((psa_algorithm_t)0x02000000)
#define PSA_ALG_CATEGORY_MAC                    ((psa_algorithm_t)0x03000000)
#define PSA_ALG_CATEGORY_CIPHER                 ((psa_algorithm_t)0x04000000)
#define PSA_ALG_CATEGORY_AEAD                   ((psa_algorithm_t)0x05000000)
#define PSA_ALG_CATEGORY_SIGN                   ((psa_algorithm_t)0x06000000)
#define PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION  ((psa_algorithm_t)0x07000000)
#define PSA_ALG_CATEGORY_KEY_DERIVATION         ((psa_algorithm_t)0x08000000)
#define PSA_ALG_CATEGORY_KEY_AGREEMENT          ((psa_algorithm_t)0x09000000)

/**
 * @brief A sufficient plaintext buffer size for @ref psa_aead_decrypt(),
 * for any of the supported key types and AEAD algorithms.
 *
 * If the size of the plaintext buffer is at least this large,
 * it is guaranteed that @ref psa_aead_decrypt() will not fail due
 * to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_DECRYPT_OUTPUT_SIZE().
 *
 * @param ciphertext_length     Size of the ciphertext in bytes.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length) \
/* implementation-defined value */

/**
 * @brief A sufficient plaintext buffer size for @ref psa_aead_decrypt(), in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed that
 * @ref psa_aead_decrypt() will not fail due to an insufficient buffer size. Depending on the
 * algorithm, the actual size of the plaintext might be smaller.
 *
 * See also @ref PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE.
 *
 * @param key_type  A symmetric key type that is compatible with algorithm alg.
 * @param alg       An AEAD algorithm: a value of type @ref psa_algorithm_t
 *                  such that @ref PSA_ALG_IS_AEAD(alg) is true.
 * @param ciphertext_length Size of the ciphertext in bytes.
 *
 * @return The AEAD plaintext size for the specified key type and algorithm.
 * If the key type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0. An implementation can return either 0 or a correct size for a key type and AEAD
 * algorithm that it recognizes, but does not support.
 */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length) \
/* implementation-defined value */

/**
 * @brief A sufficient ciphertext buffer size for @ref psa_aead_encrypt(),
 * for any of the supported key types and AEAD algorithms.
 *
 * If the size of the ciphertext buffer is at least this large,
 * it is guaranteed that @ref psa_aead_encrypt() will not fail due to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_ENCRYPT_OUTPUT_SIZE().
 *
 * @param plaintext_length Size of the plaintext in bytes.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length) \
/* implementation-defined value */

/**
 * @brief A sufficient ciphertext buffer size for @ref psa_aead_encrypt(), in bytes.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * @ref psa_aead_encrypt() will not fail due to an insufficient buffer size. Depending on the
 * algorithm, the actual size of the ciphertext might be smaller.
 *
 * See also @ref PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE.
 *
 * @param key_type A symmetric key type that is compatible with algorithm alg.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 * @param plaintext_length Size of the plaintext in bytes.
 *
 * @return The AEAD ciphertext size for the specified key type and algorithm.
 * If the key type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0. An implementation can return either 0 or a correct size for a key type and AEAD
 * algorithm that it recognizes, but does not support.
 */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length) \
/* implementation-defined value */

/**
 * @brief A sufficient ciphertext buffer size for @ref psa_aead_finish(),
 * for any of the supported key types and AEAD algorithms.
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * @ref psa_aead_finish() will not fail due to an insufficient ciphertext buffer size.
 *
 * See also @ref PSA_AEAD_FINISH_OUTPUT_SIZE().
 */
#define PSA_AEAD_FINISH_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * @brief A sufficient ciphertext buffer size for psa_aead_finish().
 *
 * If the size of the ciphertext buffer is at least this large, it is guaranteed that
 * @ref psa_aead_finish() will not fail due to an insufficient ciphertext buffer size. The actual
 * size of the output might be smaller in any given call.
 *
 * See also @ref PSA_AEAD_FINISH_OUTPUT_MAX_SIZE.
 *
 * @param key_type A symmetric key type that is compatible with algorithm alg.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 *
 * @return A sufficient ciphertext buffer size for the specified key type and algorithm.
 * If the key type or AEAD algorithm is not recognized, or the parameters are incompatible,
 * return 0. An implementation can return either 0 or a correct size for a key type and AEAD
 * algorithm that it recognizes, but does not support.
 */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) \
/* implementation-defined value */

/**
 * @brief The default nonce size for an AEAD algorithm, in bytes.
 *
 * If the size of the nonce buffer is at least this large, it is guaranteed that
 * @ref psa_aead_generate_nonce() will not fail due to an insufficient buffer size.
 *
 * For most AEAD algorithms, @ref PSA_AEAD_NONCE_LENGTH() evaluates to the exact size of
 * the nonce generated by @ref psa_aead_generate_nonce().
 *
 * See also @ref PSA_AEAD_NONCE_MAX_SIZE.
 *
 * @param key_type A symmetric key type that is compatible with algorithm alg.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 *
 * @return The default nonce size for the specified key type and algorithm. If the key type or AEAD
 * algorithm is not recognized, or the parameters are incompatible, return 0. An implementation can
 * return either 0 or a correct size for a key type and AEAD algorithm that it recognizes, but does
 * not support.
 */
#define PSA_AEAD_NONCE_LENGTH(key_type, alg) /* implementation-defined value */

/**
 * @brief A sufficient buffer size for storing the nonce generated by
 * @ref psa_aead_generate_nonce(), for any of the supported key types and AEAD algorithms.
 *
 * If the size of the nonce buffer is at least this large, it is guaranteed that
 * @ref psa_aead_generate_nonce() will not fail due to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_NONCE_LENGTH().
 */
#define PSA_AEAD_NONCE_MAX_SIZE /* implementation-defined value */

/**
 * @brief This macro returns a suitable initializer for an AEAD operation object of type
 * @ref psa_aead_operation_t.
 */
#define PSA_AEAD_OPERATION_INIT /* implementation-defined value */

/**
 * @brief The length of a tag for an AEAD algorithm, in bytes.
 *
 * This is the size of the tag output from @ref psa_aead_finish().
 * If the size of the tag buffer is at least this large, it is guaranteed that
 * @ref psa_aead_finish() will not fail due to an insufficient tag buffer size.
 *
 * See also @ref PSA_AEAD_TAG_MAX_SIZE.
 *
 * @param key_type The type of the AEAD key.
 * @param key_bits The size of the AEAD key in bits.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 *
 * @return The tag length for the specified algorithm and key. If the AEAD algorithm does not have
 * an identified tag that can be distinguished from the rest of the ciphertext, return 0. If the
 * AEAD algorithm is not recognized, return 0. An implementation can return either 0 or a correct
 * size for an AEAD algorithm that it recognizes, but does not support.
 */
#define PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg) \
/* implementation-defined value */

/**
 * @brief A sufficient buffer size for storing the tag output by @ref psa_aead_finish(),
 * for any of the supported key types and AEAD algorithms.
 *
 * If the size of the tag buffer is at least this large, it is guaranteed that
 * @ref psa_aead_finish() will not fail due to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_TAG_LENGTH().
 */
#define PSA_AEAD_TAG_MAX_SIZE /* implementation-defined value */

/**
 * @brief A sufficient output buffer size for @ref psa_aead_update(), for any of the supported key
 * types and AEAD algorithms.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * @ref psa_aead_update() will not fail due to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_UPDATE_OUTPUT_SIZE().
 *
 * @param input_length Size of the input in bytes.
 */
#define PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length) \
/* implementation-defined value */

/**
 * @brief A sufficient output buffer size for @ref psa_aead_update().
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * @ref psa_aead_update() will not fail due to an insufficient buffer size. The actual size of the
 * output might be smaller in any given call.
 *
 * See also @ref PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE.
 *
 * @param key_type A symmetric key type that is compatible with algorithm alg.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 * @param input_length Size of the input in bytes.
 *
 * @return A sufficient output buffer size for the specified key type and algorithm. If the key
 * type or AEAD algorithm is not recognized, or the parameters are incompatible, return 0. An
 * implementation can return either 0 or a correct size for a key type and AEAD algorithm that it
 * recognizes, but does not support.
 */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length) \
/* implementation-defined value */

/**
 * @brief A sufficient output buffer size for @ref psa_aead_update(), for any of the supported key
 * types and AEAD algorithms.
 *
 * If the size of the output buffer is at least this large, it is guaranteed that
 * @ref psa_aead_update() will not fail due to an insufficient buffer size.
 *
 * See also @ref PSA_AEAD_UPDATE_OUTPUT_SIZE().
 *
 * @param input_length Size of the input in bytes.
 */
#define PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE /* implementation-defined value */

/**
 * @brief A sufficient plaintext buffer size for @ref psa_aead_verify(), in bytes.
 *
 * If the size of the plaintext buffer is at least this large, it is guaranteed that
 * @ref psa_aead_verify() will not fail due to an insufficient plaintext buffer size. The actual
 * size of the output might be smaller in any given call.
 *
 * See also @ref PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE.
 *
 * @param key_type A symmetric key type that is compatible with algorithm alg.
 * @param alg An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 * @ref PSA_ALG_IS_AEAD(alg) is true.
 *
 * @return A sufficient plaintext buffer size for the specified key type and algorithm. If the key
 * type or AEAD algorithm is not recognized, or the parameters are incompatible, return 0. An
 * implementation can return either 0 or a correct size for a key type and AEAD algorithm that it
 * recognizes, but does not support.
 */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg) \
/* implementation-defined value */

/**
 * @brief Macro to build an AEAD minimum-tag-length wildcard algorithm.
 *
 * A key with a minimum-tag-length AEAD wildcard algorithm as permitted algorithm policy can be
 * used with all AEAD algorithms sharing the same base algorithm, and where the tag length of the
 * specific algorithm is equal to or larger then the minimum tag length specified by the wildcard
 * algorithm.
 *
 * @note
 * When setting the minimum required tag length to less than the smallest tag length allowed by the
 * base algorithm, this effectively becomes an ‘any-tag-length-allowed’ policy for that base
 * algorithm.
 *
 * The AEAD algorithm with a default length tag can be recovered using
 * @ref PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG().
 *
 * @param aead_alg  An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 *                  @ref PSA_ALG_IS_AEAD(aead_alg) is true.
 * @param min_tag_length    Desired minimum length of the authentication tag in bytes. This must be
 *                          at least 1 and at most the largest allowed tag length of the algorithm.
 * @return  The corresponding AEAD wildcard algorithm with the specified minimum tag length
 *          Unspecified if @c aead_alg is not a supported AEAD algorithm or if @c min_tag_length is
 *          less than 1 or too large for the specified AEAD algorithm.
 */
#define PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(aead_alg, min_tag_length) \
    /* specification-defined value */

/**
 * @brief An AEAD algorithm with the default tag length.
 *
 * This macro can be used to construct the AEAD algorithm with default tag length from an
 * AEAD algorithm with a shortened tag. See also @ref PSA_ALG_AEAD_WITH_SHORTENED_TAG().
 *
 * Compatible key types:
 * The resulting AEAD algorithm is compatible with the same key types as the
 * AEAD algorithm used to construct it.
 */
#define PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg) \
    ((((aead_alg) & ~0x003f0000) == 0x05400100) ? PSA_ALG_CCM : \
     (((aead_alg) & ~0x003f0000) == 0x05400200) ? PSA_ALG_GCM : \
     (((aead_alg) & ~0x003f0000) == 0x05000500) ? PSA_ALG_CHACHA20_POLY1305 : \
     PSA_ALG_NONE)

/**
 * @brief Macro to build a AEAD algorithm with a shortened tag.
 *
 * An AEAD algorithm with a shortened tag is similar to the corresponding AEAD algorithm, but has
 * an authentication tag that consists of fewer bytes. Depending on the algorithm, the tag length
 * might affect the calculation of the ciphertext.
 *
 * The AEAD algorithm with a default length tag can be recovered using
 * @ref PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG().
 *
 * Compatible key types:
 * The resulting AEAD algorithm is compatible with the same key types as the AEAD algorithm used to
 * construct it.
 *
 * @param aead_alg      An AEAD algorithm: a value of type @ref psa_algorithm_t such that
 *                      @ref PSA_ALG_IS_AEAD(aead_alg) is true.
 * @param tag_length    Desired length of the authentication tag in bytes.
 *
 * @return  The corresponding AEAD algorithm with the specified tag length.
 *          Unspecified if @c aead_alg is not a supported AEAD algorithm or if @c tag_length is not
 *          valid for the specified AEAD algorithm.
 */
#define PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length) \
    ((psa_algorithm_t) (((aead_alg) & ~0x003f0000) | (((tag_length) & 0x3f) << 16)))

/**
 * @brief When setting a hash-and-sign algorithm in a key policy, permit any hash algorithm.
 *
 * This value can be used to form the permitted algorithm attribute of a key policy for a signature
 * algorithm that is parametrized by a hash. A key with this policy can then be used to perform
 * operations using the same signature algorithm parametrized with any supported hash. A signature
 * algorithm created using this macro is a wildcard algorithm, and @ref PSA_ALG_IS_WILDCARD() will
 * return true.
 *
 * This value must not be used to build other algorithms that are parametrized over a hash. For any
 * valid use of this macro to build an algorithm alg, @ref PSA_ALG_IS_HASH_AND_SIGN(alg) is true.
 * This value must not be used to build an algorithm specification to perform an operation. It is
 * only valid for setting the permitted algorithm in a key policy.
 *
 * Usage:
 * For example, suppose that @c PSA_xxx_SIGNATURE is one of the following macros:
 * - @ref PSA_ALG_RSA_PKCS1V15_SIGN
 * - @ref PSA_ALG_RSA_PSS
 * - @ref PSA_ALG_RSA_PSS_ANY_SALT
 * - @ref PSA_ALG_ECDSA
 * - @ref PSA_ALG_DETERMINISTIC_ECDSA
 *
 * The following sequence of operations shows how @ref PSA_ALG_ANY_HASH can be used in a key policy:
 *
 * -#   Set the key usage flags using @ref PSA_ALG_ANY_HASH, for example:
 *      @code
 *      psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE); // or VERIFY_MESSAGE
 *      psa_set_key_algorithm(&attributes, PSA_xxx_SIGNATURE(PSA_ALG_ANY_HASH));
 *      @endcode
 * -#   Import or generate key material.
 * -#   Call @ref psa_sign_message() or @ref psa_verify_message(), passing an algorithm built from
 *      @c PSA_xxx_SIGNATURE and a specific hash. Each call to sign or verify a message can use a
 *      different hash algorithm.
 *      @code
 *      psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA_256), ...);
 *      psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA_512), ...);
 *      psa_sign_message(key, PSA_xxx_SIGNATURE(PSA_ALG_SHA3_256), ...);
 *      @endcode
 */
#define PSA_ALG_ANY_HASH ((psa_algorithm_t)0x020000ff)

#define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg) \
    ((psa_algorithm_t) (0x06000700 | ((hash_alg) & 0x000000ff)))

/**
 * @brief Macro to construct the MAC algorithm with a full length MAC, from a truncated MAC algorithm.
 *
 * @param mac_alg   A MAC algorithm identifier (value of type psa_algorithm_t such that PSA_ALG_IS_MAC(alg) is true).
 *                  This can be a truncated or untruncated MAC algorithm.
 *
 * @return  The corresponding MAC algorithm with a full length MAC.
 *          Unspecified if alg is not a supported MAC algorithm. *
 */
#define PSA_ALG_FULL_LENGTH_MAC(mac_alg) \
    ((psa_algorithm_t) ((mac_alg) & ~0x003f0000))

#define PSA_ALG_HKDF(hash_alg) \
    ((psa_algorithm_t) (0x08000100 | ((hash_alg) & 0x000000ff)))


#define PSA_ALG_GET_HASH(alg) \
        (((alg) & PSA_ALG_HASH_MASK) == 0 ? ((psa_algorithm_t)0) : PSA_ALG_CATEGORY_HASH | ((alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_HMAC_BASE   (0x03800000)
/**
 * @brief Macro to build an HMAC message-authentication-code algorithm from an underlying hash algorithm.
 *
 * For example, PSA_ALG_HMAC(PSA_ALG_SHA_256) is HMAC-SHA-256.
 * The HMAC construction is defined in HMAC: Keyed-Hashing for Message Authentication [RFC2104].
 *
 * @param hash_alg A hash algorithm (PSA_ALG_XXX value such that PSA_ALG_IS_HASH(hash_alg) is true).
 *
 * @return The corresponding HMAC algorithm. Unspecified if hash_alg is not a supported hash algorithm.
 */
#define PSA_ALG_HMAC(hash_alg) \
        ((psa_algorithm_t) (PSA_ALG_HMAC_BASE | ((hash_alg) & PSA_ALG_HASH_MASK)))

/**
 * @brief Whether the specified algorithm is a symmetric cipher algorithm.
 *
 * @param alg   An algorithm identifier (value of type #psa_algorithm_t).
 *
 * @return      1 if alg is a symmetric cipher algorithm, 0 otherwise.
 *              This macro may return either 0 or 1 if alg is not a supported
 *              algorithm identifier.
 */
#define PSA_ALG_IS_CIPHER(alg)                                          \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_CIPHER)

#define PSA_ALG_IS_AEAD(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == 0x05000000)

#define PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) \
    (((alg) & 0x7f400000) == 0x05400000)

#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == 0x07000000)

#define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) \
    (((alg) & 0x7fc00000) == 0x03c00000)

#define PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) \
    (((alg) & ~0x000000ff) == 0x06000700)

#define PSA_ALG_IS_ECDH(alg) \
    (((alg) & 0x7fff0000) == 0x09020000)

#define PSA_ALG_IS_FFDH(alg) \
    (((alg) & 0x7fff0000) == 0x09010000)

#define PSA_ALG_IS_ECDSA(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_SIGN)

#define PSA_ALG_IS_HASH(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_HASH)

#define PSA_ALG_HMAC_GET_HASH(hmac_alg)                             \
    (PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_IS_HASH_AND_SIGN(alg) \
    (PSA_ALG_IS_RSA_PSS(alg) || PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) || PSA_ALG_IS_ECDSA(alg))

#define PSA_ALG_IS_HKDF(alg) \
    (((alg) & ~0x000000ff) == 0x08000100)

#define PSA_ALG_IS_HMAC(alg) \
    (((alg) & 0x7fc0ff00) == 0x03800000)

#define PSA_ALG_IS_KEY_AGREEMENT(alg) \
    (((alg) & 0x7f000000) == 0x09000000)

#define PSA_ALG_IS_KEY_DERIVATION(alg) \
    (((alg) & 0x7f000000) == 0x08000000)

#define PSA_ALG_IS_MAC(alg) \
    (((alg) & 0x7f000000) == 0x03000000)

#define PSA_ALG_IS_RANDOMIZED_ECDSA(alg) \
    (((alg) & ~0x000000ff) == 0x06000600)

#define PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) \
    (((alg) & 0x7f00ffff) == 0x09000000)

#define PSA_ALG_IS_RSA_OAEP(alg) \
    (((alg) & ~0x000000ff) == 0x07000300)

#define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) \
    (((alg) & ~0x000000ff) == 0x06000200)

#define PSA_ALG_IS_RSA_PSS(alg) \
    (((alg) & ~0x000000ff) == 0x06000300)

#define PSA_ALG_IS_SIGN(alg) \
    (((alg) & 0x7f000000) == 0x06000000)

#define PSA_ALG_IS_SIGN_HASH(alg) \
    PSA_ALG_IS_SIGN(alg)

#define PSA_ALG_IS_SIGN_MESSAGE(alg) \
    (PSA_ALG_IS_SIGN(alg) && \
     (alg) != PSA_ALG_ECDSA_ANY && (alg) != PSA_ALG_RSA_PKCS1V15_SIGN_RAW)

#define PSA_ALG_IS_STREAM_CIPHER(alg) \
    (((alg) & 0x7f800000) == 0x04800000)

#define PSA_ALG_IS_TLS12_PRF(alg) \
    (((alg) & ~0x000000ff) == 0x08000200)

#define PSA_ALG_IS_TLS12_PSK_TO_MS(alg) \
    (((alg) & ~0x000000ff) == 0x08000300)

#define PSA_ALG_IS_WILDCARD(alg) \
    (PSA_ALG_GET_HASH(alg) == PSA_ALG_HASH_ANY)

#define PSA_ALG_KEY_AGREEMENT(ka_alg, kdf_alg) \
    ((ka_alg) | (kdf_alg))

#define PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) \
    ((psa_algorithm_t)((alg) & 0xffff0000))

#define PSA_ALG_KEY_AGREEMENT_GET_KDF(alg) \
    ((psa_algorithm_t)((alg) & 0xfe00ffff))

#define PSA_ALG_HASH_MASK   ((psa_algorithm_t)0x000000ff)

#define PSA_ALG_CBC_MAC     ((psa_algorithm_t)0x03c00100)
#define PSA_ALG_CMAC        ((psa_algorithm_t)0x03c00200)

#define PSA_ALG_CBC_NO_PADDING  ((psa_algorithm_t)0x04404000)
#define PSA_ALG_CBC_PKCS7       ((psa_algorithm_t)0x04404100)
#define PSA_ALG_ECB_NO_PADDING  ((psa_algorithm_t)0x04404400)
#define PSA_ALG_XTS             ((psa_algorithm_t)0x0440ff00)
#define PSA_ALG_CTR             ((psa_algorithm_t)0x04c01000)
#define PSA_ALG_CFB             ((psa_algorithm_t)0x04c01100)
#define PSA_ALG_OFB             ((psa_algorithm_t)0x04c01200)
#define PSA_ALG_STREAM_CIPHER   ((psa_algorithm_t)0x04800100)

#define PSA_ALG_CHACHA20_POLY1305   ((psa_algorithm_t)0x05100500)
#define PSA_ALG_CCM                 ((psa_algorithm_t)0x05500100)
#define PSA_ALG_GCM                 ((psa_algorithm_t)0x05500200)

#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW   ((psa_algorithm_t) 0x06000200)

#define PSA_ALG_ECDSA_BASE      ((psa_algorithm_t) 0x06000600)

/**
 * @brief ECDSA signature with hashing.
 *
 * This is the ECDSA signature scheme defined by ANSI X9.62,
 * with a random per-message secret number (*k*).
 *
 * The representation of the signature as a byte string consists of
 * the concatentation of the signature values *r* and *s*. Each of
 * *r* and *s* is encoded as an *N*-octet string, where *N* is the length
 * of the base point of the curve in octets. Each value is represented
 * in big-endian order (most significant octet first).
 *
 * @param hash_alg      A hash algorithm (@c PSA_ALG_XXX value such that
 *                      @ref PSA_ALG_IS_HASH(hash_alg) is true).
 *                      This includes @ref PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * @return              The corresponding ECDSA signature algorithm.
 * @return              Unspecified if hash_alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_ECDSA(hash_alg)                                 \
    (PSA_ALG_ECDSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_ECDSA_ANY       PSA_ALG_ECDSA_BASE

#define PSA_ALG_RSA_PKCS1V15_CRYPT ((psa_algorithm_t)0x07000200)
#define PSA_ALG_FFDH ((psa_algorithm_t)0x09010000)
#define PSA_ALG_ECDH ((psa_algorithm_t)0x09020000)

#define PSA_ALG_RSA_OAEP(hash_alg) \
    ((psa_algorithm_t)(0x07000300 | ((hash_alg) & 0x000000ff)))

#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg) \
    ((psa_algorithm_t)(0x06000200 | ((hash_alg) & 0x000000ff)))

#define PSA_ALG_RSA_PSS(hash_alg) \
    ((psa_algorithm_t)(0x06000300 | ((hash_alg) & 0x000000ff)))

#define PSA_ALG_TLS12_PRF(hash_alg) \
    ((psa_algorithm_t) (0x08000200 | ((hash_alg) & 0x000000ff)))

#define PSA_ALG_TLS12_PSK_TO_MS(hash_alg) \
    ((psa_algorithm_t) (0x08000300 | ((hash_alg) & 0x000000ff)))

#define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length) \
    ((psa_algorithm_t) (((mac_alg) & ~0x003f0000) | (((mac_length) & 0x3f) << 16)))

#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
/* implementation-defined value */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
/* implementation-defined value */

#define PSA_DH_FAMILY_RFC7919 ((psa_dh_family_t) 0x03)
#define PSA_ECC_FAMILY_BRAINPOOL_P_R1 ((psa_ecc_family_t) 0x30)
#define PSA_ECC_FAMILY_FRP ((psa_ecc_family_t) 0x33)
#define PSA_ECC_FAMILY_MONTGOMERY ((psa_ecc_family_t) 0x41)
#define PSA_ECC_FAMILY_SECP_K1 ((psa_ecc_family_t) 0x17)
#define PSA_ECC_FAMILY_SECP_R1 ((psa_ecc_family_t) 0x12)
#define PSA_ECC_FAMILY_SECP_R2 ((psa_ecc_family_t) 0x1b)
#define PSA_ECC_FAMILY_SECT_K1 ((psa_ecc_family_t) 0x27)
#define PSA_ECC_FAMILY_SECT_R1 ((psa_ecc_family_t) 0x22)
#define PSA_ECC_FAMILY_SECT_R2 ((psa_ecc_family_t) 0x2b)

#define PSA_HASH_BLOCK_LENGTH(alg) /* implementation-defined value */
#define PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH ((size_t)4)
#define PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) \
/* specification-defined value */
#define PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) \
/* specification-defined value */
#define PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE /* implementation-defined value */
#define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) /* specification-defined value */

#define PSA_KEY_DERIVATION_INPUT_CONTEXT /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_INFO /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_LABEL /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SALT /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SECRET /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SEED /* implementation-defined value */
#define PSA_KEY_DERIVATION_OPERATION_INIT /* implementation-defined value */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY \
/* implementation-defined value */
#define PSA_KEY_ID_NULL ((psa_key_id_t)0)
#define PSA_KEY_ID_USER_MAX ((psa_key_id_t)0x3fffffff)
#define PSA_KEY_ID_USER_MIN ((psa_key_id_t)0x00000001)
#define PSA_KEY_ID_VENDOR_MAX ((psa_key_id_t)0x7fffffff)
#define PSA_KEY_ID_VENDOR_MIN ((psa_key_id_t)0x40000000)

#define PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence, location) \
((location) << 8 | (persistence))

#define PSA_KEY_LIFETIME_GET_LOCATION(lifetime) \
((psa_key_location_t) ((lifetime) >> 8))

#define PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) \
((psa_key_persistence_t) ((lifetime) & 0x000000ff))

#define PSA_KEY_LIFETIME_IS_VOLATILE(lifetime) \
(PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) == PSA_KEY_PERSISTENCE_VOLATILE)

#define PSA_KEY_LIFETIME_PERSISTENT ((psa_key_lifetime_t) 0x00000001)
#define PSA_KEY_LIFETIME_VOLATILE ((psa_key_lifetime_t) 0x00000000)

#define PSA_KEY_LOCATION_LOCAL_STORAGE          ((psa_key_location_t) 0x000000)
#define PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT ((psa_key_location_t) 0x000001)

#define PSA_KEY_LOCATION_VENDOR_FLAG            ((psa_key_location_t)0x800000)

#define PSA_KEY_LOCATION_SE_MIN (PSA_KEY_LOCATION_VENDOR_FLAG)
#define PSA_KEY_LOCATION_SE_MAX ((psa_key_location_t) 0x8000ff)

#define PSA_KEY_PERSISTENCE_DEFAULT ((psa_key_persistence_t) 0x01)
#define PSA_KEY_PERSISTENCE_READ_ONLY ((psa_key_persistence_t) 0xff)
#define PSA_KEY_PERSISTENCE_VOLATILE ((psa_key_persistence_t) 0x00)

/**
 * @brief Vendor-defined key type flag.
 *
 * Key types defined by this standard will never have the
 * #PSA_KEY_TYPE_VENDOR_FLAG bit set. Vendors who define additional key types
 * must use an encoding with the #PSA_KEY_TYPE_VENDOR_FLAG bit set and should
 * respect the bitwise structure used by standard encodings whenever practical.
 */
#define PSA_KEY_TYPE_VENDOR_FLAG                    ((psa_key_type_t)0x8000)

#define PSA_KEY_TYPE_CATEGORY_MASK                  ((psa_key_type_t)0x7000)
#define PSA_KEY_TYPE_CATEGORY_RAW                   ((psa_key_type_t)0x1000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC             ((psa_key_type_t)0x2000)
#define PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY            ((psa_key_type_t)0x4000)
#define PSA_KEY_TYPE_CATEGORY_KEY_PAIR              ((psa_key_type_t)0x7000)

#define PSA_KEY_TYPE_CATEGORY_FLAG_PAIR             ((psa_key_type_t)0x3000)

#define PSA_KEY_TYPE_AES ((psa_key_type_t)0x2400)
#define PSA_KEY_TYPE_ARC4 ((psa_key_type_t)0x2002)
#define PSA_KEY_TYPE_CAMELLIA ((psa_key_type_t)0x2403)
#define PSA_KEY_TYPE_CHACHA20 ((psa_key_type_t)0x2004)
#define PSA_KEY_TYPE_DERIVE ((psa_key_type_t)0x1200)
#define PSA_KEY_TYPE_DES ((psa_key_type_t)0x2301)

#define PSA_KEY_TYPE_DH_GET_FAMILY(type) \
    ((psa_dh_family_t) ((type) & 0x00ff))

#define PSA_KEY_TYPE_DH_KEY_PAIR(group) \
    ((psa_key_type_t) (0x7200 | (group)))

#define PSA_KEY_TYPE_DH_PUBLIC_KEY(group) \
    ((psa_key_type_t) (0x4200 | (group)))

#define PSA_KEY_TYPE_ECC_GET_FAMILY(type) \
    ((psa_ecc_family_t) ((type) & 0x00ff))

#define PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE            ((psa_key_type_t)0x4100)
#define PSA_KEY_TYPE_ECC_KEY_PAIR_BASE              ((psa_key_type_t)0x7100)
#define PSA_KEY_TYPE_ECC_CURVE_MASK                 ((psa_key_type_t)0x00ff)

/**
 * @brief Elliptic curve key pair.
 *
 * The size of an elliptic curve key is the bit size associated with the curve,
 * i.e. the bit size of *q* for a curve over a field *F<sub>q</sub>*.
 * See the documentation of `PSA_ECC_FAMILY_xxx` curve families for details.
 *
 * @param curve     A value of type ::psa_ecc_family_t that
 *                  identifies the ECC curve to be used.
 */
#define PSA_KEY_TYPE_ECC_KEY_PAIR(curve)         \
    (PSA_KEY_TYPE_ECC_KEY_PAIR_BASE | (curve))

#define PSA_KEY_TYPE_ECC_GET_CURVE(type) \
        (type & ~PSA_KEY_TYPE_ECC_KEY_PAIR_BASE)
/**
 * @brief Elliptic curve public key.
 *
 * The size of an elliptic curve public key is the same as the corresponding
 * private key.
 *
 * @param curve     A value of type psa_ecc_family_t that
 *                  identifies the ECC curve to be used.
 */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Elliptic curve public key. */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Whether a key type is an elliptic curve key (pair or public-only). */
#define PSA_KEY_TYPE_IS_ECC(type) \
    ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff00) == 0x4100)

/** Whether a key type is an elliptic curve key pair. */
#define PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type) \
    (((type) & 0xff00) == 0x7100)

#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type) \
    (((type) & 0xff00) == 0x4100)

/**
 * @brief   The public key type corresponding to a key pair type.
 *          You may also pass a key pair type as type, it will be left unchanged.
 *
 * @param type      A public key type or key pair type.
 *
 * @return          The corresponding public key type.
 *                  If type is not a public key or a key pair,
 *                  the return value is undefined.
 */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) \
    ((psa_key_type_t) ((type) & ~0x3000))

/**
 * @brief HMAC key.
 *
 * The key policy determines which underlying hash algorithm the key can be used for.
 *
 * The bit size of an HMAC key must be a non-zero multiple of 8. An HMAC key is typically the same
 * size as the output of the underlying hash algorithm.
 *
 * @note PSA_HASH_LENGTH(alg) provides the output size of hash algorithm alg, in bytes.
 * PSA_HASH_BLOCK_LENGTH(alg) provides the block size of hash algorithm alg, in bytes.
 */
#define PSA_KEY_TYPE_HMAC ((psa_key_type_t)0x1100)

/**
 * @brief Whether a key type is asymmetric: either a key pair or a public key.
 *
 * @param type  A key type (value of type psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type) \
        (((type) & 0x4000) == 0x4000)

#define PSA_KEY_TYPE_IS_DH(type) \
    ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) & 0xff00) == 0x4200)

#define PSA_KEY_TYPE_IS_DH_KEY_PAIR(type) \
    (((type) & 0xff00) == 0x7200)

#define PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(type) \
    (((type) & 0xff00) == 0x4200)

/**
 * @brief Whether a key type is a key pair containing a private part and a public part.
 *
 * @param type  A key type (value of type psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_KEY_PAIR(type) \
    (((type) & 0x7000) == 0x7000)

/**
 * @brief Whether a key type is the public part of a key pair.
 *
 * @param type  A key type (value of type psa_key_type_t).
 */

#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type) \
    (((type) & 0x7000) == 0x4000)

/**
 * @brief Whether a key type is an RSA key. This includes both key pairs and public keys.
 *
 * @param type  A key type (value of type psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_RSA(type) \
    (PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) == 0x4001)

/**
 * @brief   Whether a key type is an unstructured array of bytes.
 *          This encompasses both symmetric keys and non-key data.
 *
 * @param type  A key type (value of type psa_key_type_t).
 */
#define PSA_KEY_TYPE_IS_UNSTRUCTURED(type) \
    (((type) & 0x7000) == 0x1000 || ((type) & 0x7000) == 0x2000)

#define PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(type) \
    ((psa_key_type_t) ((type) | 0x3000))

#define PSA_KEY_TYPE_NONE ((psa_key_type_t)0x0000)

#define PSA_KEY_TYPE_RAW_DATA ((psa_key_type_t)0x1001)
#define PSA_KEY_TYPE_RSA_KEY_PAIR ((psa_key_type_t)0x7001)
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY ((psa_key_type_t)0x4001)
#define PSA_KEY_TYPE_SM4 ((psa_key_type_t)0x2405)

#define PSA_KEY_USAGE_CACHE ((psa_key_usage_t)0x00000004)
#define PSA_KEY_USAGE_COPY ((psa_key_usage_t)0x00000002)
#define PSA_KEY_USAGE_DECRYPT ((psa_key_usage_t)0x00000200)
#define PSA_KEY_USAGE_DERIVE ((psa_key_usage_t)0x00004000)
#define PSA_KEY_USAGE_ENCRYPT ((psa_key_usage_t)0x00000100)
#define PSA_KEY_USAGE_EXPORT ((psa_key_usage_t)0x00000001)
#define PSA_KEY_USAGE_SIGN_HASH ((psa_key_usage_t)0x00001000)
#define PSA_KEY_USAGE_SIGN_MESSAGE ((psa_key_usage_t)0x00000400)
#define PSA_KEY_USAGE_VERIFY_HASH ((psa_key_usage_t)0x00002000)
#define PSA_KEY_USAGE_VERIFY_MESSAGE ((psa_key_usage_t)0x00000800)


#define PSA_MAC_OPERATION_INIT /* implementation-defined value */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits) \
/* implementation-defined value */
#define PSA_SIGNATURE_MAX_SIZE /* implementation-defined value */
#define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE /* implementation-defined value */

/**
 * @brief The action was completed successfully.
 */
#define PSA_SUCCESS ((psa_status_t)0)

/**
 * @brief An error occurred that does not correspond to any defined failure cause.
 */
#define PSA_ERROR_GENERIC_ERROR ((psa_status_t)-132)

/**
 * @brief The requested operation or a parameter is not supported by this implementation.
 */
#define PSA_ERROR_NOT_SUPPORTED ((psa_status_t)-134)

/**
 * @brief The requested action is denied by a policy.
 */
#define PSA_ERROR_NOT_PERMITTED ((psa_status_t)-133)

/**
 * @brief An output buffer is too small.
 */
#define PSA_ERROR_BUFFER_TOO_SMALL ((psa_status_t)-138)

/**
 * @brief Asking for an item that already exists.
 */
#define PSA_ERROR_ALREADY_EXISTS ((psa_status_t)-139)

/**
 * @brief Asking for an item that doesn’t exist.
 */
#define PSA_ERROR_DOES_NOT_EXIST ((psa_status_t)-140)

/**
 * @brief The requested action cannot be performed in the current state.
 */
#define PSA_ERROR_BAD_STATE ((psa_status_t)-137)

/**
 * @brief The parameters passed to the function are invalid.
 */
#define PSA_ERROR_INVALID_ARGUMENT ((psa_status_t)-135)

/**
 * @brief There is not enough runtime memory.
 */
#define PSA_ERROR_INSUFFICIENT_MEMORY ((psa_status_t)-141)

/**
 * @brief There is not enough persistent storage.
 */
#define PSA_ERROR_INSUFFICIENT_STORAGE ((psa_status_t)-142)

/**
 * @brief There was a communication failure inside the implementation.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)

/**
 * @brief There was a storage failure that might have led to data loss.
 */
#define PSA_ERROR_STORAGE_FAILURE ((psa_status_t)-146)

/**
 * @brief Stored data has been corrupted.
 */
#define PSA_ERROR_DATA_CORRUPT ((psa_status_t)-152)

/**
 * @brief Data read from storage is not valid for the implementation.
 */
#define PSA_ERROR_DATA_INVALID ((psa_status_t)-153)

/**
 * @brief A hardware failure was detected.
 */
#define PSA_ERROR_HARDWARE_FAILURE ((psa_status_t)-147)

/**
 * @brief A tampering attempt was detected.
 */
#define PSA_ERROR_CORRUPTION_DETECTED ((psa_status_t)-151)

/**
 * @brief There is not enough entropy to generate random data needed
 * for the requested action.
 */
#define PSA_ERROR_INSUFFICIENT_ENTROPY ((psa_status_t)-148)

/**
 * @brief The signature, MAC or hash is incorrect.
 */
#define PSA_ERROR_INVALID_SIGNATURE ((psa_status_t)-149)

/**
 * @brief The decrypted padding is incorrect.
 */
#define PSA_ERROR_INVALID_PADDING ((psa_status_t)-150)

/**
 * @brief Return this error when there’s insufficient data when
 * attempting to read from a resource.
 */
#define PSA_ERROR_INSUFFICIENT_DATA ((psa_status_t)-143)

/**
 * @brief The key identifier is not valid.
 */
#define PSA_ERROR_INVALID_HANDLE ((psa_status_t)-136)


/**
 * @brief An invalid algorithm identifier value.
 *
 * Zero is not the encoding of any algorithm.
 */
#define PSA_ALG_NONE ((psa_algorithm_t)0)

/* PSA Hash Algorithms*/

/**
 * @brief The MD2 message-digest algorithm.
 *
 * \warning The MD2 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD2 ((psa_algorithm_t)0x02000001)

/**
 * @brief The MD4 message-digest algorithm.
 *
 * \warning The MD4 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD4 ((psa_algorithm_t)0x02000002)

/**
 * @brief The MD5 message-digest algorithm.
 *
 * \warning The MD5 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD5 ((psa_algorithm_t)0x02000003)

/**
 * @brief The RIPEMD-160 message-digest algorithm.
 */
#define PSA_ALG_RIPEMD160 ((psa_algorithm_t)0x02000004)

/**
 * @brief The SHA-1 message-digest algorithm.
 *
 * \warning The SHA-1 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_SHA_1 ((psa_algorithm_t)0x02000005)

/**
 * @brief The SHA-224 message-digest algorithm.
 */
#define PSA_ALG_SHA_224     ((psa_algorithm_t)0x02000008) /** SHA-224 */

/**
 * @brief The SHA-256 message-digest algorithm.
 */
#define PSA_ALG_SHA_256     ((psa_algorithm_t)0x02000009) /** SHA-256 */

/**
 * @brief The SHA-384 message-digest algorithm.
 */
#define PSA_ALG_SHA_384     ((psa_algorithm_t)0x0200000a) /** SHA-384 */

/**
 * @brief The SHA-512 message-digest algorithm.
 */
#define PSA_ALG_SHA_512     ((psa_algorithm_t)0x0200000b) /** SHA-512 */

/**
 * @brief The SHA-512/224 message-digest algorithm.
 */
#define PSA_ALG_SHA_512_224 ((psa_algorithm_t)0x0200000c) /** SHA-512/224 */

/**
 * @brief The SHA-512/256 message-digest algorithm.
 */
#define PSA_ALG_SHA_512_256 ((psa_algorithm_t)0x0200000d) /** SHA-512/256 */

/**
 * @brief The SHA3-224 message-digest algorithm.
 */
#define PSA_ALG_SHA3_224    ((psa_algorithm_t)0x02000010) /** SHA-3-224 */

/**
 * @brief The SHA3-256 message-digest algorithm.
 */
#define PSA_ALG_SHA3_256    ((psa_algorithm_t)0x02000011) /** SHA-3-256 */

/**
 * @brief The SHA3-384 message-digest algorithm.
 */
#define PSA_ALG_SHA3_384    ((psa_algorithm_t)0x02000012) /** SHA-3-384 */

/**
 * @brief The SHA3-512 message-digest algorithm.
 */
#define PSA_ALG_SHA3_512    ((psa_algorithm_t)0x02000013) /** SHA-3-512 */

/**
 * @brief The SM3 message-digest algorithm.
 */
#define PSA_ALG_SM3         ((psa_algorithm_t)0x02000014) /** SM3 */


#endif /* PSA_CRYPTO_VALUES_H */
