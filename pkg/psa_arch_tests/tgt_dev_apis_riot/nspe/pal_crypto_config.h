/** @file
 * Copyright (c) 2019-2020, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

/*
 * \file pal_crypto_config.h
 *
 * \brief Configuration options for crypto tests (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively for crypto test suite
 */

#ifndef _PAL_CRYPTO_CONFIG_H_
#define _PAL_CRYPTO_CONFIG_H_

#include "riotbuild.h"
#include "autoconf.h"

/**
 * @def ARCH_TEST_RSA
 *
 * Enable the RSA public-key cryptosystem.
 * By default all supported keys are enabled.
 *
 * Comment macros to disable the types
 */
#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_1024) || \
    defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_2048) || \
    defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_3072)
#define ARCH_TEST_RSA
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_1024)
#define ARCH_TEST_RSA_1024
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_2048)
#define ARCH_TEST_RSA_2048
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_RSA_3072)
#define ARCH_TEST_RSA_3072
#endif

/**
 * @def  ARCH_TEST_ECC
 * @def  ARCH_TEST_ECC_CURVE_SECPXXXR1
 *
 * Enable the elliptic curve
 * Enable specific curves within the Elliptic Curve
 * module.  By default all supported curves are enabled.
 *
 * Requires: ARCH_TEST_ECC
 * Comment macros to disable the curve
 */
#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P192R1) || \
    defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P224R1) || \
    defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P256R1) || \
    defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P384R1)
#define ARCH_TEST_ECC
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P192R1)
#define ARCH_TEST_ECC_CURVE_SECP192R1
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P224R1)
#define ARCH_TEST_ECC_CURVE_SECP224R1
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P256R1)
#define ARCH_TEST_ECC_CURVE_SECP256R1
#endif

#if defined(CONFIG_MODULE_PSA_ASYMMETRIC_ECC_P384R1)
#define ARCH_TEST_ECC_CURVE_SECP384R1
#endif

/**
 * @def ARCH_TEST_AES
 *
 * Enable the AES block cipher.
 * By default all supported keys are enabled.
 *
 * Comment macros to disable the types
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CBC) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_128_ECB) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_192_CBC) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_192_ECB) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_256_CBC) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_256_ECB) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_512_CBC) || \
    defined(CONFIG_MODULE_PSA_CIPHER_AES_512_ECB)
#define ARCH_TEST_AES
#endif

#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CBC) || defined(CONFIG_MODULE_PSA_CIPHER_AES_128_ECB)
#define ARCH_TEST_AES_128
#endif

#if defined(CONFIG_MODULE_PSA_CIPHER_AES_192_CBC) || defined(CONFIG_MODULE_PSA_CIPHER_AES_192_ECB)
#define ARCH_TEST_AES_192
#endif

#if defined(CONFIG_MODULE_PSA_CIPHER_AES_256_CBC) || defined(CONFIG_MODULE_PSA_CIPHER_AES_256_ECB)
#define ARCH_TEST_AES_256
#endif

#if defined(CONFIG_MODULE_PSA_CIPHER_AES_512_CBC) || defined(CONFIG_MODULE_PSA_CIPHER_AES_512_ECB)
#define ARCH_TEST_AES_512
#endif

/**
 * @def  ARCH_TEST_DES
 *
 * Enable the DES block cipher.
 * By default all supported keys are enabled.
 *
 * Comment macros to disable the types
 */
// #define ARCH_TEST_DES
// #define ARCH_TEST_DES_1KEY
// #define ARCH_TEST_DES_2KEY
// #define ARCH_TEST_DES_3KEY

/**
 * @def  ARCH_TEST_RAW
 *
 * A "key" of this type cannot be used for any cryptographic operation.
 * Applications may use this type to store arbitrary data in the keystore.
 */
#define ARCH_TEST_RAW

/**
 * @def ARCH_TEST_CIPHER
 *
 * Enable the generic cipher layer.
 */
#if defined(CONFIG_MODULE_PSA_CIPHER)
#define ARCH_TEST_CIPHER
#endif

/**
 * @def ARCH_TEST_ARC4
 *
 * Enable the ARC4 key type.
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_ARC4)
#define ARCH_TEST_ARC4
#endif

/**
 * @def ARCH_TEST_CIPHER_MODE_CTR
 *
 * Enable Counter Block Cipher mode (CTR) for symmetric ciphers.
 *
 * Requires: ARCH_TEST_CIPHER
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CTR)
#define ARCH_TEST_CIPHER_MODE_CTR
#endif
/**
 * @def ARCH_TEST_CIPHER_MODE_CFB
 *
 * Enable Cipher Feedback mode (CFB) for symmetric ciphers.
 *
 * Requires: ARCH_TEST_CIPHER
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CTR)
#define ARCH_TEST_CIPHER_MODE_CFB
#endif
/**
 * @def ARCH_TEST_CIPHER_MODE_CBC
 *
 * Enable Cipher Block Chaining mode (CBC) for symmetric ciphers.
 *
 * Requires: ARCH_TEST_CIPHER
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CBC)
#define ARCH_TEST_CIPHER_MODE_CBC
#endif

/**
 * @def ARCH_TEST_CTR_AES
 *
 * Requires: ARCH_TEST_CIPHER, ARCH_TEST_AES, ARCH_TEST_CIPHER_MODE_CTR
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CTR)
#define ARCH_TEST_CTR_AES
#endif

/**
 * @def ARCH_TEST_CBC_AES
 *
 * Requires: ARCH_TEST_CIPHER, ARCH_TEST_AES, ARCH_TEST_CIPHER_MODE_CBC
 *
 * Comment macros to disable the types
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CBC)
#define ARCH_TEST_CBC_AES
#define ARCH_TEST_CBC_NO_PADDING
#endif

/**
 * @def ARCH_TEST_CBC_NO_PADDING
 *
 * Requires: ARCH_TEST_CIPHER, ARCH_TEST_CIPHER_MODE_CBC
 *
 * Comment macros to disable the types
 */
// #define ARCH_TEST_CBC_NO_PADDING

/**
 * @def ARCH_TEST_CFB_AES
 *
 * Requires: ARCH_TEST_CIPHER, ARCH_TEST_AES, ARCH_TEST_CIPHER_MODE_CFB
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CFB)
#define ARCH_TEST_CFB_AES
#endif
/**
 * @def ARCH_TEST_PKCS1V15_*
 *
 * Enable support for PKCS#1 v1.5 encoding.
 * Enable support for PKCS#1 v1.5 operations.
 * Enable support for RSA-OAEP
 *
 * Requires: ARCH_TEST_RSA, ARCH_TEST_PKCS1V15
 *
 * Comment macros to disable the types
 */
#ifdef ARCH_TEST_RSA
#define ARCH_TEST_PKCS1V15
#define ARCH_TEST_RSA_PKCS1V15_SIGN
#define ARCH_TEST_RSA_PKCS1V15_SIGN_RAW
#define ARCH_TEST_RSA_PKCS1V15_CRYPT
#define ARCH_TEST_RSA_OAEP
#endif

/**
 * @def ARCH_TEST_CBC_PKCS7
 *
 * Requires: ARCH_TEST_CIPHER_MODE_CBC
 *
 * Comment macros to disable the types
 */
#if defined(CONFIG_MODULE_PSA_CIPHER_AES_128_CBC_PKCS7)
#define ARCH_TEST_CBC_PKCS7
#endif

/**
 * @def ARCH_TEST_ASYMMETRIC_ENCRYPTION
 *
 * Enable support for Asymmetric encryption algorithms
 */
#define ARCH_TEST_ASYMMETRIC_ENCRYPTION

/**
 * @def ARCH_TEST_HASH
 *
 * Enable the hash algorithm.
 */
#if defined(CONFIG_MODULE_PSA_HASH)
#define ARCH_TEST_HASH
#endif

/**
 * @def  ARCH_TEST_HMAC
 *
 * The key policy determines which underlying hash algorithm the key can be
 * used for.
 *
 * Requires: ARCH_TEST_HASH
 */
#ifdef ARCH_TEST_HMAC
#define ARCH_TEST_HMAC
#endif
/**
 * @def ARCH_TEST_MDX
 * @def ARCH_TEST_SHAXXX
 *
 * Enable the MDX algorithm.
 * Enable the SHAXXX algorithm.
 *
 * Requires: ARCH_TEST_HASH
 *
 * Comment macros to disable the types
 */

#if defined(CONFIG_MODULE_PSA_HASH_MD2)
#define ARCH_TEST_MD2
#endif

#if defined(CONFIG_MODULE_PSA_HASH_MD4)
#define ARCH_TEST_MD4
#endif

#if defined(CONFIG_MODULE_PSA_HASH_MD5)
#define ARCH_TEST_MD5
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_1)
#define ARCH_TEST_SHA1
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_224)
#define ARCH_TEST_SHA224
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_256)
#define ARCH_TEST_SHA256
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_384)
#define ARCH_TEST_SHA384
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_512)
#define ARCH_TEST_SHA512
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_512_224)
#define ARCH_TEST_SHA512_224
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_512_256)
#define ARCH_TEST_SHA512_256
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_3_224)
#define ARCH_TEST_SHA3_224
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_3_256)
#define ARCH_TEST_SHA3_256
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_3_384)
#define ARCH_TEST_SHA3_384
#endif

#if defined(CONFIG_MODULE_PSA_HASH_SHA_3_512)
#define ARCH_TEST_SHA3_512
#endif


#if defined(CONFIG_MODULE_PSA_HASH_RIPEMD_160)
#define ARCH_TEST_RIPEMD160
#endif


/**
 * @def ARCH_TEST_HKDF
 *
 * Enable the HKDF algorithm (RFC 5869).
 *
 * Requires: ARCH_TEST_HASH
*/
#ifdef ARCH_TEST_HASH
#define ARCH_TEST_HKDF
#endif

/**
 * @def ARCH_TEST_xMAC
 *
 * Enable the xMAC (Cipher/Hash/G-based Message Authentication Code) mode for block
 * ciphers.
 * Requires: ARCH_TEST_AES or ARCH_TEST_DES
 *
 * Comment macros to disable the types
 */
#ifdef ARCH_TEST_AES
#define ARCH_TEST_CMAC
#define ARCH_TEST_GMAC
#endif

#ifdef ARCH_TEST_HASH
#define ARCH_TEST_HMAC
#endif

/**
 * @def ARCH_TEST_CCM
 *
 * Enable the Counter with CBC-MAC (CCM) mode for 128-bit block cipher.
 *
 * Requires: ARCH_TEST_AES
 */
#ifdef ARCH_TEST_AES
#define ARCH_TEST_CCM
#endif
/**
 * @def ARCH_TEST_GCM
 *
 * Enable the Galois/Counter Mode (GCM) for AES.
 *
 * Requires: ARCH_TEST_AES
 *
 */
#ifdef ARCH_TEST_AES
#define ARCH_TEST_GCM
#endif
/**
 * @def ARCH_TEST_TRUNCATED_MAC
 *
 * Enable support for RFC 6066 truncated HMAC in SSL.
 *
 * Comment this macro to disable support for truncated HMAC in SSL
 */
#define ARCH_TEST_TRUNCATED_MAC


/**
 * @def ARCH_TEST_ECDH
 *
 * Enable the elliptic curve Diffie-Hellman library.
 *
 * Requires: ARCH_TEST_ECC
 */
#define ARCH_TEST_ECDH

/**
 * @def ARCH_TEST_ECDSA
 *
 * Enable the elliptic curve DSA library.
 * Requires: ARCH_TEST_ECC
 */
#define ARCH_TEST_ECDSA

/**
 * @def ARCH_TEST_DETERMINISTIC_ECDSA
 *
 * Enable deterministic ECDSA (RFC 6979).
*/
#define ARCH_TEST_DETERMINISTIC_ECDSA

/**
 * @def ARCH_TEST_ECC_ASYMMETRIC_API_SUPPORT
 *
 * Enable ECC support for asymmetric API.
*/
//#define ARCH_TEST_ECC_ASYMMETRIC_API_SUPPORT
#include "pal_crypto_config_check.h"

#endif /* _PAL_CRYPTO_CONFIG_H_ */
