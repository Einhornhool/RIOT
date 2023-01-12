#ifndef MBEDTLS_PSA_ERROR_H
#define MBEDTLS_PSA_ERROR_H

#include "mbedtls/error.h"
#include "psa/crypto.h"

psa_status_t mbedtls_to_psa_error(int ret);

#endif /* MBEDTLS_PSA_ERROR_H */
