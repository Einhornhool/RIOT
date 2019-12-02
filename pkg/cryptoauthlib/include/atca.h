/**
* @defgroup     
* @ingroup      pkg
* @brief
* @{
*
* @file
* @brief
*
* More detailed information about the file and the functionality implemented.
*
* @author      
*
*/

#ifndef CRYPTOAUTHLIB_CONTRIB_H
#define CRYPTOAUTHLIB_CONTRIB_H

#include "periph/i2c.h"
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For ATECC508A*/
#ifndef ATCA_I2C_ADR
#define ATCA_I2C_ADR (0x60)    /**< Default device adress is 0xC0. We need to shift it by 1, to ignore lsb (rw bit) */
#endif

/**
 * @brief   Device descriptor contains ATCAIfaceCfg structure
 */
typedef struct {
    ATCAIfaceCfg params;        /**< device configuration */
} atca_t;

/**
 * @brief   ATCA device init
 */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOAUTHLIB_CONTRIB_H */
/** @} */