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
#define ATCA_I2C_ADR (0xC0)    /**< Default device adress is 0xC0. We need to shift it by 1, to ignore lsb (rw bit) */
#endif

#define ATCA_SLEEP_ADR  (0x01)           /**< Address to write byte to enter sleep mode */
#define ATCA_IDLE_ADR   (0x02)            /**< Address to write byte to enter idle mode */
#define ATCA_DATA_ADR   (0x03)            /**< Word Address to read and write to data area */

/**
 * @brief   Device descriptor contains ATCAIfaceCfg structure
 */
typedef struct {
    ATCAIfaceCfg params;        /**< device configuration */
} atca_t;

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOAUTHLIB_CONTRIB_H */
/** @} */