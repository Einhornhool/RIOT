#include "periph/i2c.h"
#include "periph/gpio.h"
#include "xtimer.h"
#include "../../sys/include/checksum/ucrc16.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Default Adresse um 1 geschoben, um rw-Bit zu ignorieren (0xC0 >> 1) */
#define DEV_ADR (0x60)
/* Word Address -> auszulesender Datenbereich */
#define WORD_ADR (0x03)

#define POLYNOM (0x8005)

#define CMD_INFO (0x30)
#define CMD_SHA (0x47)

#define INFO_EXEC_TIME (1000)  //0,1 ms == 100 us –> typical exec time –> max = 1 ms
#define SHA_EXEC_TIME (9000)

#define DATA_SIZE(input) (input)

void i2c_wakeup(void)
{
    /* SDA als GPIO, Output */
    gpio_init(GPIO_PIN(0, 16), GPIO_OUT);
    gpio_clear(GPIO_PIN(0, 16));

    /* 0 us warten (t(WLO)) */
    xtimer_usleep(30);

    /* i2c-Device reinitialisieren */
    i2c_init(I2C_DEV(0));

    /* 1500 us warten (t(WHI)) */
    xtimer_usleep(1500);
}

uint8_t getNumberOfElements(char input[64])
{
    uint8_t count = 0;

    for (int i = 0; input[i] != '\0'; i++)
    {
        count++;
    }

    return count;
}

uint16_t atCRC(size_t length, const uint8_t *data)
{
    size_t counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
        {
            data_bit = (data[counter] & shift_register) ? 1 : 0;
            crc_bit = crc_register >> 15;
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }
    return crc_register;
}

typedef struct __attribute__((__packed__))
{
    uint8_t count;
    uint8_t opcode;
    uint8_t param1;
    uint16_t param2;
    uint8_t checksum[2];
} InfoCmd_t;

typedef struct __attribute__((__packed__))
{
    uint8_t count;
    uint8_t opcode;
    uint8_t param1;
    uint16_t param2;
    uint8_t data[66];
} SHACmd_t;

void infoCmd(void)
{
    InfoCmd_t infoCmd;
    
    infoCmd.opcode = CMD_INFO;
    infoCmd.param1 = 0;
    infoCmd.param2 = 0;
    infoCmd.count = sizeof(infoCmd);

    /* sizeof(infoCmd) minus checksum-bytes */
    // uint16_t checksum = ucrc16_calc_le(&(infoCmd.count), sizeof(infoCmd)-2, POLYNOM, 0);
    uint16_t checksum = atCRC(5, &(infoCmd.count));
    infoCmd.checksum[0] = checksum & 0x00FF;
    infoCmd.checksum[1] = checksum >> 8;

    i2c_wakeup();
    i2c_write_regs(I2C_DEV(0), DEV_ADR, WORD_ADR, &infoCmd, sizeof(infoCmd), 0);

    /* 0,1 ms warten (Max Cmd Execution Time) */
    xtimer_usleep(INFO_EXEC_TIME);

    i2c_read_bytes(I2C_DEV(0), DEV_ADR, &infoCmd, sizeof(infoCmd), 0);
}

void addInput(char *data, char *input)
{
    for
}

void shaCmd(char input[64])
{
    SHACmd_t shaCmd;

    shaCmd.opcode = CMD_SHA;
    shaCmd.param1 = 0x02;
    shaCmd.param2 = 0;
    
    strncpy(shaCmd.data, input, getNumberOfElements(input));
    
    shaCmd.count = sizeof(shaCmd);

}

int main (void)
{
    
    return 0;
}
