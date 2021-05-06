#ifndef PERIPH_HASHES_CONTEXT_H
#define PERIPH_HASHES_CONTEXT_H

#include <stdlib.h>
#include "kernel_defines.h"
#include "cryptocell_incl/crys_hash.h"
#include "psa/crypto.h"

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA1)
typedef CRYS_HASHUserContext_t psa_hashes_sha1_operation_t;
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA256)
typedef CRYS_HASHUserContext_t psa_hashes_sha256_operation_t;
#endif

#endif