#include "periph/i2c.h"
#include "periph/gpio.h"
#include "xtimer.h"
#include "../../sys/include/checksum/ucrc16.h"
#include <stdint.h>
#include <stdlib.h>

/*Default Adresse um 1 geschoben, um rw-Bit zu ignorieren (0xC0 >> 1)*/
#define DEV_ADR (0x60)
/*Word Address -> auszulesender Datenbereich*/
#define READ_REG (0x03)

#define POLYNOM (0x8005)
#define CMD_INFO (0x30)
#define CMD_EXEC_TIME (100)  //0,1 ms == 100 us –> typical exec time –> max = 1 ms
#define DATA_SIZE (0)

void i2c_wakeup(void)
{
    //SDA als GPIO, Output
    gpio_init(GPIO_PIN(0, 16), GPIO_OUT);
    gpio_clear(GPIO_PIN(0, 16));

    //60 us warten (t(WLO))
    xtimer_usleep(30);

    //i2c-Device reinitialisieren
    i2c_init(I2C_DEV(0));

    //1500 us warten (t(WHI))
    xtimer_usleep(1500);
}

typedef struct __attribute__((__packed__)) Content
{
    uint8_t opcode;
    uint8_t param1;
    uint16_t param2;
} Content_t;

typedef struct __attribute__((__packed__)) Packet
{
    uint8_t count;
    Content_t content;
    uint16_t checksum;
} Packet_t;

int main (void)
{
    Content_t cont;
    Packet_t infoCmd;
    cont.opcode = CMD_INFO;
    cont.param1 = 0;
    cont.param2 = 0;

    infoCmd.content = cont;
    infoCmd.checksum = ucrc16_calc_le((const uint8_t*) &cont, sizeof(cont), POLYNOM, 0);
    infoCmd.count = sizeof(infoCmd);

    i2c_wakeup();
    i2c_write_bytes(I2C_DEV(0), DEV_ADR, &infoCmd, sizeof(infoCmd), 0);
    //0,1 ms warten (t(WLO))
    xtimer_usleep(100);

    i2c_read_bytes(I2C_DEV(0), DEV_ADR, &infoCmd, sizeof(infoCmd), 0);
    // uint32_t data = 0;
    // //Daten auslesen
    // i2c_read_regs(I2C_DEV(0), DEV_ADR, READ_REG, &data, 4, 0);
    return 0;
}
