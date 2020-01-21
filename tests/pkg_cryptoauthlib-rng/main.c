/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Application to generate random numbers based on ATCA hardware
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdint.h>

#include "atca.h"
#include "atca_params.h"

int main(void)
{
    uint8_t randout[4];
    while(1) {
        atcab_random(randout);
        printf("%02x%02x%02x%02x\n", randout[0], randout[1], randout[2], randout[3]);
        atca_delay_ms(500);
    }

    return 0;
}
