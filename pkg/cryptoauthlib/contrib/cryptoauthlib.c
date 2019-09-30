#include <stdint.h>
#include <stdio.h>

#include "periph/i2c.h"
#include "periph_conf.h"
#include "cryptoauthlib.h"
#include "atca_hal.h"

#include "xtimer.h"

/* For ATECC508A*/
/* Default adresse shifted by 1, to ignore lsb (rw bit) (0xC0 >> 1) */
#define DEV_ADR (0x60)
/* Word Address -> data area to read */
#define WORD_ADR (0x03)

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */


/** \brief This function delays for a number of microseconds.
 *
 * \param[in] delay number of microseconds to delay
 */
void atca_delay_us(uint32_t delay)
{
    xtimer_usleep(delay);
}

/** \brief This function delays for a number of tens of microseconds.
 *
 * \param[in] delay number of 0.01 milliseconds to delay
 */
void atca_delay_10us(uint32_t delay)
{
    xtimer_usleep(delay * 10);
}

/** \brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * \param[in] delay number of milliseconds to delay
 */

/* ASF already has delay_ms - see delay.h */
void atca_delay_ms(uint32_t delay)
{
    xtimer_usleep(delay * 1000);
}

ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    i2c_init(I2C_DEV(0));
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{

}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    if (i2c_read_regs(I2C_DEV(0), DEV_ADR, WORD_ADR, rxdata, *rxlength))
    {
        
    }
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{

}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{

}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{

}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    if(i2c_release(I2C_DEV(0)) == -1)
    {
        return ATCA_COMM_FAIL;
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found)
{
    return ATCA_UNIMPLEMENTED;
}