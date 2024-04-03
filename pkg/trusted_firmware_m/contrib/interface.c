/*
 * Copyright (c) 2017-2021, Arm Limited. All rights reserved.
 * Copyright (c) 2023 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/* This file provides implementation of TF-M NS os wrapper functions for the
 * RTOS use case. This implementation provides multithread safety, so it
 * can be used in RTOS environment.
 */

#include <stdint.h>
// #include "mutex.h"
#include "tfm_ns_interface.h"

#define ENABLE_DEBUG 1
#include "debug.h"

// static mutex_t ns_mutex;

int32_t tfm_ns_interface_dispatch(veneer_fn fn,
                                  uint32_t arg0, uint32_t arg1,
                                  uint32_t arg2, uint32_t arg3)
{
    int32_t result;
    // DEBUG("[tfm interface] Interface Dispatch\n");

    // /* TFM request protected by NS lock */
    // while (mutex_trylock(&ns_mutex) != 0) {
    //     DEBUG("[tfm interface] In Mutex While Loop\n");
    // }

    result = fn(arg0, arg1, arg2, arg3);

    // mutex_unlock(&ns_mutex);

    return result;
}

uint32_t tfm_ns_interface_init(void)
{
    DEBUG("[tfm interface] Interface Init\n");
    // mutex_init(&ns_mutex);

    return 0;
}
