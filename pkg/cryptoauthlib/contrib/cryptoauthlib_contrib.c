#include <stdint.h>
#include <stdio.h>
#include "cryptoauthlib_contrib.h"
#include "atca_params.h"
#include "xtimer.h"

#include "errno.h"
#include "periph/i2c.h"
#include "periph/gpio.h"
#include "periph_conf.h"

#include "cryptoauthlib.h"
#include "hal/atca_hal.h"

#define DEV_ADR (0x60)

/* Word Address -> data area to read */
#define WORD_ADR (0x03)
#define DEVICE (I2C_DEV(0))

// void init_atca_cfg(ATCAIfaceCfg *cfg)
// {
//     cfg->iface_type             = ATCA_I2C_IFACE;
//     cfg->devtype                = ATECC508A;
//     cfg->atcai2c.slave_address  = ATCA_I2C_ADDRESS;
//     cfg->atcai2c.bus            = 0;
//     cfg->atcai2c.baud           = 400000;
//     cfg->wake_delay             = 1500;
//     cfg->rx_retries             = 20;
// }

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

/* HAL I2C implementation */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    i2c_init(DEVICE);
    // i2c_acquire(ATCA_PARAM_I2C);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    int ret = -1; /* return value from riot functions */
    
    /* First byte in command packages is reserved for HAL layer use as needed
    We use it for the word address value 0x03 */
    txdata[0] = ATCA_DATA_ADR;

    /* reserved byte isn't included in txlength, yet, so we add 1 */
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
    int ret = -1; /* return value of riot functions */
    uint8_t length_package[1] = { 0 };

    /* read first byte (size of output-data) and store it in length_package
    to check if output will fit into rxdata */
    while (retries-- > 0 && ret != 0)
    {
        ret = i2c_read_byte(DEVICE, DEV_ADR, length_package, 0);
    }
    if (ret != 0)
    {
        return ATCA_RX_TIMEOUT;
    }

    uint8_t bytes_to_read = length_package[0]-1;

    if (bytes_to_read > *rxlength)
    {
        return ATCA_SMALL_BUFFER;
    }

    /* insert length_package into rxdata as first byte (first byte of output 
    data is always the count) if we don't do this crc will be wrong */
    rxdata[0] = length_package[0];

    /* reset ret and retries to read the rest of the output */
    ret = -1;
    retries = iface->mIfaceCFG->rx_retries;

    /* read rest of output and insert into rxdata array after first byte */
    while (retries-- > 0 && ret != 0)
    {
        ret = i2c_read_bytes(DEVICE, DEV_ADR, (rxdata + 1), bytes_to_read, 0);
    }

    if (ret != 0)
    {
        return ATCA_RX_TIMEOUT;
    }

    *rxlength = length_package[0];

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    /* ATCA_PARAM_I2C needs to be woken up by holding sda pin low for some time and then reinitializing it */
    
    /* SDA as GPIO, Output to manually set it to low */
    gpio_init(GPIO_PIN(0, 16), GPIO_OUT);
    gpio_clear(GPIO_PIN(0, 16));

    /* wait 30 us (t(WLO)) */
    xtimer_usleep(30);

    /* reinitialize i2c-ATCA_PARAM_I2C */
    i2c_init(I2C_DEV(0));

    /* wait 1500 us (t(WHI)) */
    xtimer_usleep(1500);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    /* idle state = write byte to register adr. 0x02 */
    uint8_t idle[1] = { 0x01 }; 
    i2c_write_regs(DEVICE, DEV_ADR, ATCA_IDLE_ADR, idle, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    /* sleep state = write byte to register adr. 0x01 */
    uint8_t sleep[1] = { 0x01 }; 
    i2c_write_regs(ATCA_PARAM_I2C, ATCA_PARAM_ADDR, ATCA_SLEEP_ADR, sleep, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    i2c_release(DEVICE);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_buses(int ATCA_PARAM_I2Ces[], int max_buses)
{
    printf("calling %s:%d\n",__FILE__, __LINE__);
    return ATCA_UNIMPLEMENTED;
}

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg *cfg, int *found)
{
    printf("calling %s:%d\n",__FILE__, __LINE__);
    return ATCA_UNIMPLEMENTED;
}