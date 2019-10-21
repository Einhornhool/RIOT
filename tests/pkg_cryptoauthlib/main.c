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

#define SHA256_HASH_SIZE (32)

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

    // uint8_t revision[4] = { 0x00, 0x00, 0x00, 0x00 };
    
    uint8_t teststring[] = "chili cheese fries";
    uint8_t hashTest[] = {0x36, 0x46, 0xEF, 0xD6, 0x27, 0x6C, 0x0D, 0xCB, 0x4B, 0x07, 0x73, 0x41, 0x88, 0xF4, 
                            0x17, 0xB4, 0x38, 0xAA, 0xCF, 0xC6, 0xAE, 0xEF, 0xFA, 0xBE, 0xF3, 0xA8, 0x5D, 0x67, 0x42, 0x0D, 0xFE, 0xE5};

    uint8_t result[SHA256_HASH_SIZE]; // +3 to fit 1 byte length and 2 bytes checksum
    memset(result, 0, SHA256_HASH_SIZE); // alles in result auf 0 setzen

    uint16_t testStringSize = (sizeof(teststring)-1); // -1 to ignore \0
    
    status = atcab_init(&cfg);
    
    // status = atcab_info(revision);
    // printf("Execution: %x\n", status);
    
    status = atcab_sha_start();
    status = atcab_sha_end(result, testStringSize, teststring);

    if (memcmp(hashTest, result, SHA256_HASH_SIZE) == 0)
    {
        printf("Success\n");
    }
    else
    {
        printf("Not a success: Error %x\n", status);
    }

    return 0;
}