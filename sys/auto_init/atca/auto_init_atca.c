

/**
 * @ingroup     sys_auto_init
 * @{
 * @file
 * @brief       initializes cryptoauthlib devices
 *
 * @author      >
 * @}
 */

#ifdef MODULE_CRYPTOAUTHLIB
#include "can/device.h"
#include "atca_params.h"

#define ATCADEV_NUMOF (ARRAY_SIZE(atca_params))


static atca_t candev_dev[CANDEV_NUMOF];
static char _can_stacks[CANDEV_NUMOF][CANDEV_STACKSIZE];
static can_t candev[CANDEV_NUMOF];

void auto_init_periph_can(void) {

    for (size_t i = 0; i < CANDEV_NUMOF; i++) {
        can_init(&candev[i], &candev_conf[i]);
        candev_dev[i].dev = (candev_t *)&candev[i];
        candev_dev[i].name = candev_params[i].name;
#ifdef MODULE_CAN_TRX
        candev_dev[i].trx = candev_params[i].trx;
#endif
#ifdef MODULE_CAN_PM
        candev_dev[i].rx_inactivity_timeout = candev_params[i].rx_inactivity_timeout;
        candev_dev[i].tx_wakeup_timeout = candev_params[i].tx_wakeup_timeout;
#endif

        can_device_init(_can_stacks[i], CANDEV_STACKSIZE, CANDEV_BASE_PRIORITY + i,
                        candev_params[i].name, &candev_dev[i]);
    }
}
#else
typedef int dont_be_pedantic;
#endif
