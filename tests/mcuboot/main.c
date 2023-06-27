/*
 * Copyright (C) 2017 Inria
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
 * @brief       MCUBoot compile test application
 *
 * @author      Francisco Acosta <francisco.acosta@inria.fr>
 *
 * @}
 */

#include <stdio.h>
#include "cpu.h"
#include "periph/gpio.h"
#include "board.h"

int main(void)
{
    puts("Hello MCUBoot!");

    printf("You are running RIOT on a(n) %s board.\n", RIOT_BOARD);
    printf("This board features a(n) %s CPU.\n", RIOT_CPU);
    printf("The startup address is: %p\n", (void*)SCB->VTOR);
    printf("LED_PORT is %p\n", (void*) LED_PORT);
    LED0_ON;

    return 0;
}
