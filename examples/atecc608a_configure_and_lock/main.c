/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Is an application to configure and lock CryptoAuth Device zones
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "atca.h"
#include "atca_params.h"

#define ENABLE_DEBUG    0
#include "debug.h"

#define SERIAL_NO_01_POS       (0)
#define REVISION_NO_POS        (4)
#define SERIAL_NO_02_POS       (8)
#define AES_ENABLE_POS         (13)
#define I2C_ENABLE_POS         (14)
#define I2C_ADDRESS_POS        (16)
#define COUNT_MATCH_POS        (18)
#define CHIP_MODE_POS          (19)
#define SLOT_CONFIG_POS        (20)
#define COUNTER_00_POS         (52)
#define COUNTER_01_POS         (60)
#define USE_LOCK_POS           (68)
#define VOLATILE_KEY_PERM_POS  (69)
#define SECURE_BOOT_POS        (70)
#define KDF_IV_LOC_POS         (72)
#define KDF_IV_STR_POS         (73)
#define USER_EXTRA_POS         (84)
#define USER_EXTRA_ADD_POS     (85)
#define LOCK_VALUE_POS         (86)
#define LOCK_CONFIG_POS        (87)
#define SLOT_LOCKED_POS        (88)
#define CHIP_OPTIONS_POS       (90)
#define X509_FORMAT_POS        (92)
#define KEY_CONFIG_POS         (96)


// static int get_serial_number(uint8_t *config, uint8_t *serial, size_t serial_buf_size)
// {
//     size_t serial_no_len = 8;
//     if (serial_buf_size < serial_no_len) {
//         return -1;
//     }

//     uint8_t *serial_01_ptr = &config[SERIAL_NO_01_POS];
//     uint8_t *serial_02_ptr = &config[SERIAL_NO_02_POS];

//     for (int i = 0; i < serial_no_len; i++) {
//         serial[i] = serial_01_ptr[i];
//         serial[i+4] = serial_02_ptr[i];
//     }

//     return serial_no_len;
// }

// static int get_revision_number(uint8_t *config, uint8_t *rev_no, size_t rev_buf_size)
// {
//     size_t rev_no_len = 4;
//     if (rev_buf_size < rev_no_len) {
//         return -1;
//     }

//     for (int i = 0; i < rev_no_len; i++) {
//         rev_no[i] = config[REVISION_NO_POS + i];
//     }

//     return rev_no_len;
// }

// static int aes_enabled(uin8_t *config)
// {
//     return (config[AES_ENABLE_POS] & 0x01);
// }

// static int i2c_enabled(uint8_t *config)
// {
//     return (config[I2C_ADDRESS_POS] & 0x01);
// }

// static int counter_match_enabled(uint8_t *config)
// {
//     return ((config[COUNT_MATCH_POS] & 0x01) != 0)
// }

// static int get_counter_match_key_slot(uint8_t *config)
// {
//     return (config[COUNT_MATCH_POS] & 0xF0);
// }

// static int custom_i2c_addr_enabled(uint8_t *config, uint8_t *i2c_addr)
// {
//     *i2c_addr = 0;

//     if (config[CHIP_MODE_POS] & 0x01)
//     {
//         *i2c_addr = config[USER_EXTRA_ADD_POS];
//     }
//     return (config[CHIP_MODE_POS] & 0x01);
// }

// static int custom_i2c_addr_is_valid(uint8_t *config)
// {
//     return (config[USER_EXTRA_ADD_POS] != 0);
// }

// static int ttl_enabled(uint8_t *config)
// {
//     /* Bit 1 must be 1 */
//     return ((config[CHIP_MODE_POS] >> 1) & 0x01);
// }

// static int watchdog_length(uint8_t *config)
// {
//     /* Bit 2: 0 = 1.3s (default, recommended), 1 = 10 s */
//     return ((config[CHIP_MODE_POS] >> 2) & 0x01);
// }

// /**
//  * @brief   Checks if the clock divider setting is valid
//  *
//  * @param   config
//  * @return  Setting value if valid
//  *          -1 if invalid
//  */
// static uint8_t clock_divider_setting(uint8_t *config)
// {
//     uint8_t clk_div_set = config[CHIP_MODE_POS] & 0xF8;
//     DEBUG("Clock Divider Setting is %05x\n", clk_div_set);

//     return ((clk_div_set == 0x00 ? clk_div_set) :
//             (clk_div_set == 0x0D ? clk_div_set) :
//             (clk_div_set == 0x5D ? clk_div_set) :
//             -1);
// }

// /**
//  * @brief   Get the slot config MS-Byte and MS-Bit first
//  *
//  * @param config
//  * @param slot_no
//  * @return uint16_t
//  */
// static uint16_t get_slot_config(uint8_t *config, int slot_no)
// {
//     uint8_t *slot_start = &config[SLOT_CONFIG_POS + (slot_no * 2)];
//     uint16_t slot_config = (((uint16_t) *slot_start + 1) << 8) | *(slot_start);
//     return slot_config;
// }

// static uint32_t get_counter(uint8_t *config, int counter_addr)
// {
//     uint32_t counter_val = 0;
//     for (int i = 0; i < 4; i++) {
//         counter_val |= ((uint32_t)config[counter_addr] << (24 - i * 8));
//     }
//     return counter_val;
// }

// /**
//  * @brief   Check whether UseLock is enabled
//  *
//  * @param   config  Pointer to device configuration
//  * @param   key_id  Will contain ID of UseLock Key, if UseLock is enabled,
//  *                  will be 0xFF if UseLock is not enabled
//  * @return  1 if enabled
//  *          0 if not enabled
//  */
// static int use_lock_enabled(uint8_t *config, uint8_t *key_id)
// {
//     *key_id = 0xFF;
//     /* Value must be 0x0A, otherwise UseLock is ignored */
//     if (config[USE_LOCK_POS] & 0x0F == 0x0A)
//     {
//         *key_id = (config[USE_LOCK_POS] & 0xF0) >> 4;
//     }
//     return (config[USE_LOCK_POS] & 0x0F == 0x0A);
// }

// static int volatile_key_permission_enabled(uint8_t *config, uint8_t *key_id)
// {
//     *key_id = 0xFF
//     if ((config[VOLATILE_KEY_PERM_POS] >> 7) & 0x01)
//     {
//         *key_id = (config[VOLATILE_KEY_PERM_POS] & 0x07);
//     }
//     return ((config[VOLATILE_KEY_PERM_POS] >> 7) & 0x01);
// }

// static uint8_t get_secure_boot_mode(uint8_t *config, uint8_t *dig_id, uint8_t *key_id)
// {
//     *dig_id = 0xFF;
//     *key_id = 0xFF;
//     if (config[SECURE_BOOT_POS] & 0x03)
//     {
//         *dig_id = (config[SECURE_BOOT_POS + 1] & 0x0F);
//         *key_id = (config[SECURE_BOOT_POS + 1] & 0xF0) >> 4;
//     }
//     return (config[SECURE_BOOT_POS] & 0x03);
// }

// static int secure_boot_persistent_enabled(uint8_t *config)
// {
//     return ((config[SECURE_BOOT_POS] >> 3) & 0x01);
// }

// static int secure_boot_rand_nonce_enabled(uint8_t *config)
// {
//     return ((config[SECURE_BOOT_POS] >> 4) & 0x01);
// }

// static int get_kdf_iv_loc(uint8_t *config)
// {
//     return (config[KDF_IV_LOC_POS]);
// }

// /**
//  * @brief   Get the KDF IV string object
//  *
//  * @param config
//  * @param str
//  * @param str_len
//  * @return  Length of string
//  *          -1 if output buffer too small
//  */
// static int get_kdf_iv_string(uint8_t *config, uint8_t *str, size_t str_len)
// {
//     uint8_t * str_pos = config + KDF_IV_STR_POS;

//     if (str_len < 2) {
//         return -1;
//     }

//     str[0] = str_pos[0];
//     str[1] = str_pos[1];

//     return 2;
// }

// static uint8_t get_user_extra(uint8_t *config)
// {
//     return config[USER_EXTRA_POS];
// }

// static int otp_and_data_locked(uint8_t *config)
// {
//     return (config[LOCK_VALUE_POS] == 0);
// }

// static int config_zone_locked(uint8_t *config)
// {
//     return (config[LOCK_CONFIG_POS] == 0);
// }

// static int slot_locked(uint8_t *config, uint8_t slot)
// {
//     if (slot > 15) {
//         return -1
//     }

//     uint16_t slot_locked = ((uint16_t)config[SLOT_LOCKED_POS + 1] << 8) | config[SLOT_LOCKED_POS];

//     /* Not locked if bit is 1, locked if bit is 0 */
//     // TODO: check byte order
//     return (((config[SLOT_LOCKED_POS] >> slot) & 0x01) ? 0 : 1);
// }

// static int power_on_selftest_enabled(uint8_t *config)
// {
//     return (config[CHIP_OPTIONS_POS] & 0x01);
// }

// static uint8_t io_protection_key_enabled(uint8_t *config,
//                                          uint8_t *key_id,
//                                          uint8_t *ecdh_prot,
//                                          uint8_t *kdf_prot)
// {
//     *key_id = 0xFF;
//     *ecdh_prot = 0xFF;
//     *kdf_prot = 0xFF;

//     if (config[CHIP_OPTIONS_POS] & 0x01)
//     {
//         *key_id = (config[CHIP_OPTIONS_POS + 1] & 0xF0) >> 4;
//         *ecdh_prot = (config[CHIP_OPTIONS_POS + 1] & 0x2);
//         *kdf_prot = (config[CHIP_OPTIONS_POS + 1] & 0xC0) >> 2;
//     }

//     return (config[CHIP_OPTIONS_POS] & 0x01);
// }

// static int kdf_aes_enabled(uint8_t *config)
// {
//     return ((config[CHIP_OPTIONS_POS] >> 2) & 0x01);
// }

// static void get_x509_validation_format(uint8_t *config,
//                                       uint8_t byte_no,
//                                       uint8_t *pub_pos,
//                                       uint8_t *templ_len)
// {
//     *pub_pos = (config[X509_FORMAT_POS + byte_no] & 0x0F);
//     *temp_len = ((config[X509_FORMAT_POS + byte_no] & 0xF0) >> 4);
// }

// /**
//  * @brief   Get the key config MS-Byte and MS-Bit first
//  *
//  * @param config
//  * @param slot_no
//  * @return uint16_t
//  */
// static uint16_t get_key_config(uint8_t *config, int slot_no)
// {
//     uint8_t *slot_start = &config[KEY_CONFIG_POS + (slot_no * 2)];
//     uint16_t key_config = (((uint16_t) *slot_start + 1) << 8) | *(slot_start);
//     return key_config;
// }

uint8_t pattern_slot_config[] = {
    0x00, 0x00, 0x00, 0x00, /* Read only serial number */
    0x00, 0x00, 0x00, 0x00, /* Read only revision number */
    0x00, 0x00, 0x00, 0x00, /* Read only serial number */
    0x00, 0x00, 0x00, 0x00, /* Read only reserved, I2C enable, reserved */
    0xC0, 0x00, 0x00, 0x00, /* I2C address, reserved, CountMatch, chip mode*/

    /*  Private keys:
        0x8720 = 1 0 0 0 | 0 1 1 1 | 0 0 1 0 | 0 0 0 0
                 7  -  4 | 3  -  0 | 15 - 12 | 11 -  8
        - External signatures of arbitrary messages enabled
        - Internal signatures of messages by GenDig/GenKey enabled
        - ECDH operations permitted
        - ECDH Master Secret will be output in the clear
        - No write by write command */
    0x87, 0x20, 0x87, 0x20, /* Slot 0, Slot 1 */
    0x87, 0x20, 0x87, 0x20, /* Slot 2, Slot 3 */

    /* Private Keys, write always allowed (use only for testing!!!)*/
    0x87, 0x00, 0x87, 0x00,

    /*  Private key:
        - as above but
        - ECDH Master Secret will be written into slot n + 1 (7)*/
    0x8F, 0x20, 0x87, 0x20, /* Slot 6, Slot 7 */

    /* Data storage and public keys, anything goes */
    0x00, 0x00, 0x00, 0x00, /* Slot 8, Slot 9 */
    0x00, 0x00, 0x00, 0x00, /* Slot 10, Slot 11 */
    0x00, 0x00, 0x00, 0x00, /* Slot 12, Slot 13 */
    0x00, 0x00, 0x00, 0x00, /* Slot 14, Slot 15 */

    0xFF, 0xFF, 0xFF, 0xFF, /* Counter 0 */
    0x00, 0x00, 0x00, 0x00, /* Counter 0 */
    0xFF, 0xFF, 0xFF, 0xFF, /* Counter 1 */
    0x00, 0x00, 0x00, 0x00, /* Counter 1 */
    0x00, 0x00, 0x00, 0x00, /* UseLock, VolatileKeyPermission, Secure Boot */
    0x00, 0x00, 0x00, 0x00, /* KdflvLoc, KdflvStr, KdflcStr, Reserved */
    0x00, 0x00, 0x00, 0x00, /* Reserved */
    0x00, 0x00, 0x00, 0x00, /* Reserved */
    0x00, 0x00, 0x55, 0x55, /* UserExtra, UserExtraAdd, LockValue, LockConfig */
    0xFF, 0xFF, 0x00, 0x00, /* 2x SlotLocked, 2x ChipOptions */
    0x00, 0x00, 0x00, 0x00, /* X509format */

    /*  Private Key, access only with Sign, GenKey, PrivWrite cmds
        Public Version can always be generated
        Slots are individually lockable with Lock command */
    0x13, 0x00, 0x13, 0x00, /* KeyConfig 0, KeyConfig 1 */
    0x13, 0x00, 0x13, 0x00, /* KeyConfig 2, KeyConfig 3 */

    /*  AES Key */
    0x18, 0x00, 0x18, 0x00, /* KeyConfig 4, KeyConfig 5 -> not usable as AES keys! */

    /*  Private Key
        - Used for ECDH
        - Slot 7 will contain corresponding Master Secret */
    0x13, 0x00, 0x1F, 0x00, /* KeyConfig 6, KeyConfig 7 */

    /* SHA Key or other data */
    0x1C, 0x00, /* KeyConfig 8 */

    /* ECC Public Keys */
    0x10, 0x00, /* KeyConfig 9 */
    0x10, 0x00, 0x10, 0x00, /* KeyConfig 10, KeyConfig 11 */
    0x10, 0x00, 0x10, 0x00, /* KeyConfig 12, KeyConfig 13 */

    /* SHA Key or other data */
    0x1C, 0x00, 0x1C, 0x00  /* KeyConfig 14, KeyConfig 15 */
};

static void get_bin(char *result, uint8_t byte)
{
    for (int i = 0; i < 8; i++) {
        result[i] = (((byte << i) & 0x80) ? '1' : '0');
    }
    result[8] = '\0';
}

static int read_config(ATCADevice dev)
{
    uint8_t data[ATCA_ECC_CONFIG_SIZE];
    uint8_t data_count = 0;
    char binary[9];

    memset(data, 0, ATCA_ECC_CONFIG_SIZE);

    int status = calib_read_config_zone(dev, data);

    if (status != ATCA_SUCCESS) {
        printf("Error reading config zone\n");
        return 1;
    }

    printf("Config zone: \n\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN0 SN1 SN2 SN3\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("RN0 RN1 RN2 RN3\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN4 SN5 SN6 SN7\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SN8 RSVD I2CE RSVD\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("I2CA RSVD OTPM CM\n");

    for (int i = 0; i < 32; i += 4) {
        int slotcount = 0;
        printf("%03d:%03d ", data_count, data_count + 3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("SC%d SC%d ", slotcount, slotcount);
        slotcount++;
        printf("SC%d SC%d\n", slotcount, slotcount);
        slotcount++;
    }

    for (int k = 0; k < 2; k++) {
        int cnt_no = 0;
        for (int i = 0; i < 8; i += 4) {
            printf("%03d:%03d ", data_count, data_count + 3);
            for (int j = 0; j < 4; j++) {
                get_bin(binary, data[data_count]);
                printf("%s ", binary);
                data_count++;
            }
            printf("CNT%d CNT%d CNT%d CNT%d\n", cnt_no, cnt_no, cnt_no, cnt_no);
        }
        cnt_no++;
    }

    for (int i = 0; i < 16; i += 4) {
        printf("%03d:%03d ", data_count, data_count + 3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("LKU%d LKU%d LKU%d LKU%d\n", i, i + 1, i + 2, i + 3);
    }

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("UE SEL LV LC\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("SL0 SL1 RFU0 RFU1\n");

    printf("%03d:%03d ", data_count, data_count + 3);
    for (int i = 0; i < 4; i++) {
        get_bin(binary, data[data_count]);
        printf("%s ", binary);
        data_count++;
    }
    printf("X509-0 X509-1 X509-2 X509-3\n");

    for (int i = 0; i < 32; i += 4) {
        int key_cnt = 0;
        printf("%03d:%03d ", data_count, data_count + 3);
        for (int j = 0; j < 4; j++) {
            get_bin(binary, data[data_count]);
            printf("%s ", binary);
            data_count++;
        }
        printf("KC%d KC%d ", key_cnt, key_cnt);
        key_cnt++;
        printf("KC%d KC%d\n", key_cnt, key_cnt);
        key_cnt++;
    }

    return 0;
}

int main(void)
{
    ATCADevice dev;
    atcab_init_ext(&dev, (ATCAIfaceCfg *)&atca_params[0].cfg);

#ifdef CONFIG_CRYPTO
    ATCA_STATUS status = calib_write_config_zone(dev, pattern_slot_config);
    if (status != ATCA_SUCCESS) {
        printf("Write went wrong: 0x%02x\n", status);
    }
#endif
#ifdef LOCK_CRYPTO
    ATCA_STATUS status = ATCA_SUCCESS;

    status = calib_lock_config_zone(dev);
    if (status != ATCA_SUCCESS) {
        printf("Lock config zone went wrong\n");
    }
    status = calib_lock_data_zone(dev);
    if (status != ATCA_SUCCESS) {
        printf("Lock data zone went wrong\n");
    }
#endif

    read_config(dev);
    bool is_locked_config = false;
    bool is_locked_data = false;
    calib_is_locked(dev, LOCK_ZONE_CONFIG, &is_locked_config);
    if (!is_locked_config) {
        printf("Config zone not locked.\n");
    }
    else {
        printf("Config zone locked.\n");
    }

    calib_is_locked(dev, LOCK_ZONE_DATA, &is_locked_data);
    if (!is_locked_data) {
        printf("Data zone not locked.\n");
    }
    else {
        printf("Data zone locked.\n");
    }
    return 0;
}
