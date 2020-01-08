/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg_cryptoauthlib
 * @{
 *
 * @file
 * @brief       HAL implementation for the library Microchip CryptoAuth devices
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdint.h>
#include "xtimer.h"
#include "periph/i2c.h"
#include "periph/gpio.h"

#include "atca.h"
#include "atca_params.h"


/* Timer functions */
void atca_delay_us(uint32_t delay)
{
    xtimer_usleep(delay);
}

void atca_delay_10us(uint32_t delay)
{
    xtimer_usleep(delay * 10);
}

void atca_delay_ms(uint32_t delay)
{
    xtimer_usleep(delay * 1000);
}

/* Hal I2C implementation */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    if (cfg->iface_type != ATCA_I2C_IFACE) {
        return ATCA_BAD_PARAM;
    }

    ((ATCAHAL_t *)hal)->hal_data = cfg;

    atcab_wakeup();

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    (void)iface;
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int ret = -1;

    /* The first byte of the command package contains the word address */
    txdata[0] = ATCA_DATA_ADDR;

    i2c_acquire(cfg->atcai2c.bus);
    ret = i2c_write_bytes(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1),
                          txdata, txlength + 1, 0);
    i2c_release(cfg->atcai2c.bus);

    if (ret != 0) {
        return ATCA_TX_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata,
                            uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t retries = cfg->rx_retries;
    uint8_t length_package = 0;
    uint8_t bytes_to_read;
    int ret = -1;

    /* Every command needs some time to be executed. We check whether the device is done
       by polling, so we don't have to wait for the max execution time. For that there's
       a number of retries (specified in the device descriptor). If polling is not successful
       this function returns an error code. */

    i2c_acquire(cfg->atcai2c.bus);
    while (retries-- > 0 && ret != 0) {
        /* read first byte (size of output data) and store it in variable length_package
           to check if output will fit into rxdata */
        ret = i2c_read_byte(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1),
                            &length_package, 0);
    }
    i2c_release(cfg->atcai2c.bus);

    if (ret != 0) {
        return ATCA_RX_TIMEOUT;
    }

    bytes_to_read = length_package - 1;

    if (bytes_to_read > *rxlength) {
        return ATCA_SMALL_BUFFER;
    }

    /* CRC function calculates value of the whole output package, so to get a correct
       result we need to include the length of the package we got before into rxdata as first byte. */
    rxdata[0] = length_package;

    /* reset ret and retries to read the rest of the output */
    ret = -1;
    retries = iface->mIfaceCFG->rx_retries;

    /* read rest of output and insert into rxdata array after first byte */
    i2c_acquire(cfg->atcai2c.bus);
    while (retries-- > 0 && ret != 0) {
        ret = i2c_read_bytes(cfg->atcai2c.bus,
                             (cfg->atcai2c.slave_address >> 1), (rxdata + 1),
                             bytes_to_read, 0);
    }
    i2c_release(cfg->atcai2c.bus);

    if (ret != 0) {
        return ATCA_RX_TIMEOUT;
    }

    *rxlength = length_package;

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    /* ATCA_PARAM_I2C needs to be woken up by holding the sda pin low for some time and then reinitializing it */
    /* SDA as GPIO, Output to manually set it to low */
    if (gpio_init(ATCA_GPIO_WAKE, GPIO_OUT) == -1) {
        return ATCA_GEN_FAIL;
    }
    gpio_clear(ATCA_GPIO_WAKE);
    /* wait 30 us (t(WLO)) */
    xtimer_usleep(WAKE_LOW_DURATION);

    /* reinitialize i2c-ATCA_PARAM_I2C */
    i2c_init(cfg->atcai2c.bus);
    /* wait 1500 us (t(WHI)) */
    xtimer_usleep(cfg->wake_delay);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    i2c_acquire(cfg->atcai2c.bus);
    i2c_write_byte(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1),
                   ATCA_IDLE_ADDR, 0);
    i2c_release(cfg->atcai2c.bus);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    i2c_acquire(cfg->atcai2c.bus);
    i2c_write_byte(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1),
                   ATCA_SLEEP_ADDR, 0);
    i2c_release(cfg->atcai2c.bus);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *)hal_data;

    i2c_release(cfg->atcai2c.bus);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    (void)i2c_buses;
    (void)max_buses;
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found)
{
    (void)bus_num;
    (void)cfg;
    (void)found;
    return ATCA_UNIMPLEMENTED;
}
