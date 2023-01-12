#ifndef PSA_MBEDTLS_HASHES_CTX_H
#define PSA_MBEDTLS_HASHES_CTX_H

#include "kernel_defines.h"

#if IS_USED(MODULE_PSA_MBEDTLS_HASHES_SHA256)
#include "mbedtls/sha256.h"
typedef mbedtls_sha256_context psa_hashes_sha256_ctx_t;
#endif

#endif /* PSA_MBEDTLS_HASHES_CTX_H */
