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

#define BUS                         (dev->p.i2c) /**< BUS */
#define ADDR                        (dev->p.addr) /**< ADDR */

/**
 * @brief   ATCA specific return values
 */
enum {
    ATCA_OK,          /**< Success, no error */
    ATCA_ERROR_BUS,   /**< I2C bus error */
    ATCA_ERROR_DEV,   /**< internal device error */
    ATCA_ERROR_CONF,  /**< invalid device configuration */
    ATCA_ERROR,       /**< general error */
};

/* For ATECC508A*/
#ifndef ATCA_I2C_ADR
#define ATCA_I2C_ADR (0x60)    /**< Default device adress is 0xC0. We need to shift it by 1, to ignore lsb (rw bit) */
#endif

#ifndef ATCA_DATA_ADR
#define ATCA_DATA_ADR (0x03)            /**< Word Address to read data area */
#endif

#define ATCA_SLEEP_ADR (0x01)           /**< Address to write byte to enter sleep mode */
#define ATCA_IDLE_ADR (0x02)            /**< Address to write byte to enter idle mode */

/**
 * @brief   Device descriptor contains ATCAIfaceCfg structure
 */
typedef struct {
    ATCAIfaceCfg params;        /**< device configuration */
} atca_t;

/**
 * @brief   ATCA device init
 */
int atca_init(atca_t *dev, const ATCAIfaceCfg *params);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTOAUTHLIB_CONTRIB_H */
/** @} */