#ifndef RIOT_NV_SEED_CONFIG_H
#define RIOT_NV_SEED_CONFIG_H

#include "riot_nv_seed.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#undef MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES

#define MBEDTLS_ENTROPY_NV_SEED
#ifndef MBEDTLS_PLATFORM_NV_SEED_READ_MACRO
#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO  riot_nv_seed_read
#endif
#ifndef MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO
#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO riot_nv_seed_write
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* RIOT_NV_SEED_CONFIG */
