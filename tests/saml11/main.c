#include "periph/i2c.h"
#include "periph/gpio.h"
#include "xtimer.h"
#include "../../sys/include/checksum/ucrc16.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Default adresse shifted by 1, to ignore lsb (rw bit) (0xC0 >> 1) */
#define DEV_ADR (0x60)
/* Word Address -> data area to read */
#define WORD_ADR (0x03)
/* polynome for crc */
#define POLYNOM (0x8005)

/* Opcodes */
#define CMD_INFO (0x30)
#define CMD_SHA (0x47)

/* max execution times */
#define INFO_EXEC_TIME (1000)
#define SHA_EXEC_TIME (9000)

#define CMD_SIZE_MIN (7) //(count = count + opcode + param1 + param2 + checksum)
#define DATA_SIZE_MAX (147) // Highest count of data sent by any command –> complete cmd-package can't be larger than 155 Bytes
#define SHA256_HASH_SIZE (32)

/*  Struct to build command packages 
    Complete package can't be larger than 155 bytes
    Size of data array is DATA_MAX_SIZE + 2 to include checksum
*/
typedef struct __attribute__((__packed__))
{
    uint8_t count;
    uint8_t opcode;
    uint8_t param1;
    uint16_t param2;
    uint8_t data[DATA_SIZE_MAX+2];
} Command_t;

void i2c_wakeup(void)
{
    /* SDA as GPIO, Output */
    gpio_init(GPIO_PIN(0, 16), GPIO_OUT);
    gpio_clear(GPIO_PIN(0, 16));

    /* wait 0 us (t(WLO)) */
    xtimer_usleep(30);

    /* reinitialize i2c-Device */
    i2c_init(I2C_DEV(0));

    /* wait 1500 us (t(WHI)) */
    xtimer_usleep(1500);
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

void infoCmd(void)
{
    Command_t infoCmd;
    
    infoCmd.opcode = CMD_INFO;
    infoCmd.param1 = 0;
    infoCmd.param2 = 0;
    infoCmd.count = sizeof(infoCmd);

    /* sizeof(infoCmd) minus checksum-bytes */
    uint16_t checksum = atCRC(infoCmd.count-2, &(infoCmd.count));
    infoCmd.data[0] = checksum & 0x00FF;
    infoCmd.data[1] = checksum >> 8;

    i2c_wakeup();
    i2c_write_regs(I2C_DEV(0), DEV_ADR, WORD_ADR, &infoCmd, sizeof(infoCmd), 0);

    /* 0,1 ms warten (Max Cmd Execution Time) */
    xtimer_usleep(INFO_EXEC_TIME);

    i2c_read_bytes(I2C_DEV(0), DEV_ADR, &infoCmd, sizeof(infoCmd), 0);
}

/*  https://passwordsgenerator.net/sha256-hash-generator/
    Test String: chili cheese fries
    Hash:  3646EFD6276C0DCB4B07734188F417B438AACFC6AEEFFABEF3A85D67420DFEE5 */

int shaCmd(void)
{
    char teststring[] = "chili cheese frie";
    uint8_t hashTest[] = {0x36, 0x46, 0xEF, 0xD6, 0x27, 0x6C, 0x0D, 0xCB, 0x4B, 0x07, 0x73, 0x41, 0x88, 0xF4, 
                            0x17, 0xB4, 0x38, 0xAA, 0xCF, 0xC6, 0xAE, 0xEF, 0xFA, 0xBE, 0xF3, 0xA8, 0x5D, 0x67, 0x42, 0x0D, 0xFE, 0xE5};

    uint8_t result[SHA256_HASH_SIZE+3];
    memset(result, 0, SHA256_HASH_SIZE+3);

    uint16_t testStringSize = sizeof(teststring) -1;

    Command_t shaCmd;

    /* Build package SHA(Start) */
    shaCmd.opcode = CMD_SHA;
    shaCmd.param1 = 0x00;
    shaCmd.param2 = 0;
    shaCmd.count = CMD_SIZE_MIN;

    uint16_t checksum = atCRC(shaCmd.count-2, &(shaCmd.count));
    shaCmd.data[0] = checksum & 0x00FF;
    shaCmd.data[1] = checksum >> 8;
    /* End of package build SHA(Start) */

    i2c_wakeup();

    /* SHA(Start) */
    i2c_write_regs(I2C_DEV(0), DEV_ADR, WORD_ADR, &shaCmd, shaCmd.count, 0);
    xtimer_usleep(SHA_EXEC_TIME);
    i2c_read_bytes(I2C_DEV(0), DEV_ADR, &shaCmd, shaCmd.count, 0);

    /* Build package SHA(End) */
    shaCmd.opcode = CMD_SHA;
    shaCmd.param1 = 0x02;
    shaCmd.param2 = testStringSize;
    shaCmd.count = CMD_SIZE_MIN + testStringSize;

    memcpy(shaCmd.data, teststring, testStringSize);

    checksum = atCRC(shaCmd.count-2, &(shaCmd.count));
    shaCmd.data[testStringSize] = checksum & 0x00FF;
    shaCmd.data[testStringSize+1] = checksum >> 8;
    /* End of package build SHA(End) */
    
    /* SHA(End) */
    i2c_write_regs(I2C_DEV(0), DEV_ADR, WORD_ADR, &shaCmd, shaCmd.count, 0);
    xtimer_usleep(SHA_EXEC_TIME);
    i2c_read_bytes(I2C_DEV(0), DEV_ADR, result, SHA256_HASH_SIZE+3, 0);

    return memcmp(hashTest, result+1, SHA256_HASH_SIZE);
}

int main (void)
{
    // infoCmd();
    int result = shaCmd();
    if ( result == 0)
    {
        printf("Success\n");
    }
    else
    {
        printf("Bitch, this is wrong\n");
    }
    

    return 0;
}
