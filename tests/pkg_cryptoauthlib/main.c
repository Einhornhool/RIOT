#include <stdio.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "atca_execution.h"
#include "periph/i2c.h"
#include "periph_conf.h"

#include <stdint.h>

#include "xtimer.h"

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
    atca_delay_us(delay * 10);
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
    atca_delay_us(delay * 1000);
}


int main(void)
{
    printf("first in main\n");
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;
    printf("%d\n", _gDevice->mCommands->dt);
    packet.param1 = INFO_MODE_REVISION;
    status = atInfo(ca_cmd, &packet);
    status = atca_execute_command(&packet, _gDevice);
    printf("second in main\n");

    printf("%d\n", status);
    return status;
}