/**
* @defgroup     
* @ingroup      pkg
* @brief
* @{
*
* @file
* @brief       Wrapper for Microchip Cryptoauthlib
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
#define ATCA_I2C_ADR (0xC0 >> 1)    /**< Default device adress shifted by 1, to ignore lsb (rw bit) */
#endif

#ifndef ATCA_DATA_ADR
#define ATCA_DATA_ADR (0x03)            /**< Word Address to read data area */
#endif

#define ATCA_SLEEP_ADR (0x01)           /**< Address to write byte to enter sleep mode */
#define ATCA_IDLE_ADR (0x02)            /**< Address to write byte to enter idle mode */

/**
 * @brief   ATCA configuration parameters
 */
typedef struct {
    i2c_t i2c;              /**< I2C bus the sensor is connected to */
    uint8_t addr;           /**< the chip's address on the I2C bus */
} atca_params_t;

/**
 * @brief   Device descriptor
 */
typedef struct {
    atca_params_t params;        /**< device configuration */
} atca_t;

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOAUTHLIB_CONTRIB_H */
/** @} */