#include <stdio.h>
#include <string.h>

#include "cryptoauthlib_contrib.h"

#include "cryptoauthlib.h"
#include "atca_execution.h"
#include "hal/atca_hal.h"
#include "periph/i2c.h"

#include "periph/gpio.h"
#include "periph_conf.h"

#include <stdint.h>

#include "xtimer.h"

#define SHA256_HASH_SIZE (32)


static ATCA_STATUS get_info(uint8_t *revision)
{
    ATCA_STATUS status;

    status = atcab_init(&cfg_ateccx08a_i2c_default);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = atcab_info(revision);
    atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_info() failed with ret=0x%08X\r\n", status);
    }

    return status;
}


static void info(void)
{
    ATCA_STATUS status;
    uint8_t revision[4];
    char displaystr[15];
    size_t displaylen = sizeof(displaystr);

    status = get_info(revision);
    if (status == ATCA_SUCCESS)
    {
        // dump revision
        atcab_bin2hex(revision, 4, displaystr, &displaylen);
        printf("revision:\r\n%s\r\n", displaystr);
    }
}


int main(void)
{
    // ATCA_STATUS status;


    // // atca_t dev;

    // // ATCAIfaceCfg cfg = {
    // //             .iface_type             = ATCA_I2C_IFACE,
    // //             .devtype                = ATECC508A,
    // //             .atcai2c.slave_address  = 0XC0,
    // //             .atcai2c.bus            = 0,
    // //             .atcai2c.baud           = 400000,
    // //             .wake_delay             = 1500,
    // //             .rx_retries             = 20
    // // };

    // // uint8_t revision[4] = { 0x00, 0x00, 0x00, 0x00 };

    // uint8_t teststring[] = "chili cheese fries";
    // uint8_t hash_test[] = {0x36, 0x46, 0xEF, 0xD6, 0x27, 0x6C, 0x0D, 0xCB, 0x4B, 0x07, 0x73, 0x41, 0x88, 0xF4, 
    //                         0x17, 0xB4, 0x38, 0xAA, 0xCF, 0xC6, 0xAE, 0xEF, 0xFA, 0xBE, 0xF3, 0xA8, 0x5D, 0x67, 0x42, 0x0D, 0xFE, 0xE5};

    // uint8_t result[SHA256_HASH_SIZE]; // +3 to fit 1 byte length and 2 bytes checksum
    // memset(result, 0, SHA256_HASH_SIZE); // alles in result auf 0 setzen

    // uint16_t test_string_size = (sizeof(teststring)-1); // -1 to ignore \0
    
    // status = atcab_init(&cfg_ateccx08a_i2c_default);

    // // status = atcab_random(result);
    // // printf("Status: %x\n", status);
    // // printf("Number: %x %x %x %x %x %x %x %x\n", 
    // // result[0], result[1], result[2],result[3], result[4],result[5],result[6],result[7]);
 
    // // status = atcab_info(revision);
    // // printf("info status= %x\n", status);
    // // printf("Revision= %x %x %x %x\n", revision[0], revision[1], revision[2], revision[3]);
 
    // status = atcab_sha_start();
    // status = atcab_sha_end(result, test_string_size, teststring);
    // if (memcmp(hash_test, result, SHA256_HASH_SIZE) == 0)
    // {
    //     printf("Success\n");
    // }
    // else
    // {
    //     printf("Not a success. Status: %x\n", status);
    // }

    info();

    return 0;
}