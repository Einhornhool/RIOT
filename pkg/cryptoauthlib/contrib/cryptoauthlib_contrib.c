#include <stdint.h>
#include <stdio.h>
#include "../include/cryptoauthlib_contrib.h"
#include "xtimer.h"

#include "errno.h"
#include "periph/i2c.h"
#include "periph/gpio.h"
#include "periph_conf.h"

#include "cryptoauthlib.h"
#include "hal/atca_hal.h"


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


ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    i2c_init(DEVICE);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    int ret = -1; // return value from riot functions
    
    // First byte in command packages is reserved for HAL layer use as needed
    // We use it for the word address value 0x03
    txdata[0] = 0x03;

    // reserved byte isn't included in txlength, yet, so we add 1
    int txlength_updated = txlength + 1;
    ret = i2c_write_bytes(DEVICE, DEV_ADR, txdata, txlength_updated, 0); 
    
    if (ret != 0)
    {
        return ATCA_TX_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    uint8_t retries = iface->mIfaceCFG->rx_retries;
    int ret = -1; // return value of riot functions
    uint8_t lengthPackage[1] = { 0 };

    // read first byte (size of output-data) and store it in lengthPackage
    // to check if it fits into rxdata
    while (retries-- > 0 && ret != 0)
    {
        ret = i2c_read_byte(DEVICE, DEV_ADR, lengthPackage, 0);
    }
    if (ret != 0)
    {
        return ATCA_RX_TIMEOUT;
    }

    uint8_t bytesToRead = lengthPackage[0]-1;

    if (bytesToRead > *rxlength)
    {
        return ATCA_SMALL_BUFFER;
    }

    // insert lengthPackage into rxdata as first byte (first byte of output data is always the count)
    // if we don't do this crc will be wrong 
    rxdata[0] = lengthPackage[0];

    // reset ret and retries to read the rest of the output
    ret = -1;
    retries = iface->mIfaceCFG->rx_retries;

    // read rest of output and insert into data array after first byte
    while (retries-- > 0 && ret != 0)
    {
        ret = i2c_read_bytes(DEVICE, DEV_ADR, rxdata+1, bytesToRead, 0);
    }

    if (ret != 0)
    {
        return ATCA_RX_TIMEOUT;
    }

    *rxlength = lengthPackage[0];

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    // Device needs to be woken up by holding sda pin low for some time and then reinitializing it
    
    // SDA as GPIO, Output to manually set it to low
    gpio_init(GPIO_PIN(0, 16), GPIO_OUT);
    gpio_clear(GPIO_PIN(0, 16));

    // wait 30 us (t(WLO))
    xtimer_usleep(30);

    // reinitialize i2c-Device
    i2c_init(I2C_DEV(0));

    // wait 1500 us (t(WHI))
    xtimer_usleep(1500);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    // idle state = write byte to register adr. 0x02
    uint8_t idle[1] = { 0x01 }; 
    i2c_write_regs(DEVICE, DEV_ADR, IDLE_ADR, idle, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    // sleep state = write byte to register adr. 0x01
    uint8_t sleep[1] = { 0x01 }; 
    i2c_write_regs(DEVICE, DEV_ADR, SLEEP_ADR, sleep, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    if(i2c_release(DEVICE) == -1)
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