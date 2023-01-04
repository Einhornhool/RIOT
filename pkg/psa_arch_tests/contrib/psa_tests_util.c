/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg_psa_arch_tests
 * @{
 *
 * @file
 * @brief       Provides utility functions called by the PSA Architecture
 *              Testsuite's PAL API.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <string.h>
#include <stdint.h>
#include "fmt.h"
#include "stdio_uart.h"

#define SIM_FLASHSIZE       (64)
#define PRINT_BUFF_SIZE     (256)

static uint8_t flash_simulation[SIM_FLASHSIZE] = { 0xFF };

void riot_uart_write(const char *str, int32_t data) {
    int len = fmt_strlen(str);
    int datalen = 0;
    char output[PRINT_BUFF_SIZE];
    int pos = 0;

    for (int i = 0; i < len; i++) {
        if (str[i] == '%') {
            switch (str[i+1]) {
                case 'd':
                case 'i':
                    datalen = fmt_s32_dec(output+pos, data);
                    pos += datalen;
                    i++;
                    break;
                case 'x':
                    datalen = fmt_u32_hex(output+pos, data);
                    pos += datalen;
                    i++;
                    break;
                default:
                    output[pos++] = str[i];
                    break;
            }
        }
        else {
            output[pos++] = str[i];
            if (pos >= PRINT_BUFF_SIZE) {
                stdio_write(output, PRINT_BUFF_SIZE);
                pos = 0;
            }
        }
    }

    if (pos) {
        stdio_write(output, pos);
    }
}

void riot_nvmem_read(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    memcpy(buffer, flash_simulation+offset, size);
}

void riot_nvmem_write(uint32_t base, uint32_t offset, void *buffer, int size)
{
    (void) base;
    memcpy(flash_simulation+offset, buffer, size);
}
