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

#ifdef __cplusplus
extern "C" {
#endif


/* For ATECC508A*/
/* Default adress shifted by 1, to ignore lsb (rw bit) */
#define ATCA_I2C_ADDRESS (0xC0 >> 1)

/* Word Address -> data area to read */
#define WORD_ADR (0x03)
#define SLEEP_ADR (0x01)
#define IDLE_ADR (0x02)
#define I2C_DEVICE (I2C_DEV(0))

/**
 * @brief   ATCA configuration parameters
 */
typedef struct {
    i2c_t i2c;              /**< I2C bus the sensor is connected to */
    uint8_t addr;           /**< the sensors address on the I2C bus */
    uint32_t atime;         /**< conversion time in microseconds */
} ATCA_params_t;

/**
 * @brief   Device descriptor
 */
typedef struct {
    ATCA_params_t p;    /**< device configuration */
    int again;              /**< amount of gain */
} ATCA_t;


ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg);
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength);
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength);
ATCA_STATUS hal_i2c_wake(ATCAIface iface);
ATCA_STATUS hal_i2c_idle(ATCAIface iface);
ATCA_STATUS hal_i2c_sleep(ATCAIface iface);
ATCA_STATUS hal_i2c_release(void *hal_data);
ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses);
ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found);

#ifdef __cplusplus
}
#endif

#endif