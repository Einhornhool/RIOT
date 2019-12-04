#include <stdint.h>
#include <stdio.h>

#include "xtimer.h"
#include "periph/i2c.h"
#include "periph/gpio.h"
#include "periph_conf.h"

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

/* HAL I2C implementation */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{   
    if(cfg->iface_type != ATCA_I2C_IFACE)
    {
        return ATCA_BAD_PARAM;
    }
    
    printf("Init params Bus: %x, Adress: %x\n", cfg->atcai2c.bus, cfg->atcai2c.slave_address);
    atca_t* dev = &atca_devs[cfg->atcai2c.bus];

    ((ATCAHAL_t*)hal)->hal_data = dev;
    
    printf("Bus: %x\n", cfg->atcai2c.bus);
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    
    int ret = -1; /* return value from riot functions */
    
    /* First byte in command packages is reserved for HAL layer use as needed
    We use it for the word address value 0x03 */
    txdata[0] = ATCA_DATA_ADR;

    /* reserved byte isn't included in txlength, yet, so we add 1 */
    int txlength_updated = txlength + 1;
    ret = i2c_write_bytes(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1), txdata, txlength_updated, 0); 
    
    if (ret != 0)
    {
        return ATCA_TX_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    uint8_t retries = cfg->rx_retries;
    int ret = -1; /* return value of riot functions */
    uint8_t length_package[1] = { 0 };

    /* read first byte (size of output-data) and store it in length_package
    to check if output will fit into rxdata */
    while (retries-- > 0 && ret != 0)
    {
        ret = i2c_read_byte(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1), length_package, 0);
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
        ret = i2c_read_bytes(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1), (rxdata + 1), bytes_to_read, 0);
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
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    /* idle state = write byte to register adr. 0x02 */
    uint8_t idle[1] = { 0x02 }; 
    i2c_write_regs(cfg->atcai2c.bus, (cfg->atcai2c.slave_address >> 1), ATCA_IDLE_ADR, idle, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    /* sleep state = write byte to register adr. 0x01 */
    uint8_t sleep[1] = { 0x01 }; 
    i2c_write_regs(ATCA_PARAM_I2C, ATCA_PARAM_ADR, ATCA_SLEEP_ADR, sleep, 1, 0);

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    atca_t* hal = (atca_t*)hal_data;
    i2c_release(hal->params.atcai2c.bus);
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