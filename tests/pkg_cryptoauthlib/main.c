#include <stdio.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "atca_execution.h"
#include "hal/atca_hal.h"
#include "periph/i2c.h"

#include "periph/gpio.h"
#include "periph_conf.h"

#include <stdint.h>

#include "xtimer.h"

int main(void)
{
    ATCA_STATUS status;

    ATCAIfaceCfg cfg = {
                .iface_type             = ATCA_I2C_IFACE,
                .devtype                = ATECC508A,
                .atcai2c.slave_address  = 0XC0,
                .atcai2c.bus            = 0,
                .atcai2c.baud           = 400000,
                .wake_delay             = 1500,
                .rx_retries             = 20
    };

    uint8_t revision[4];
    
    status = atcab_init(&cfg);
    printf("%x\n", status);
    status = atcab_info(revision);
    printf("%x\n", status);

    // uint8_t serial[4];
    // atcab_read_serial_number(serial);
    // printf("%d %d\n", serial[0], serial[1]);

    return 0;
}