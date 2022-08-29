/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto cpu_nrf52
 * @{
 *
 * @file
 * @brief       Utility functions to enable and disable the CryptoCell 310 engine on the nrf52840dk
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#ifndef CRYPTOCELL_UTIL_H
#define CRYPTOCELL_UTIL_H

/**
 * @brief   Enables CryptoCell module and IRQs on nrf52840.
 *
 *          Must be called before using crypto functions.
 */
void cryptocell_enable(void);

/**
 * @brief   Disables CryptoCell module and IRQs on nrf52840.
 *
 *          Should be called after using crypto functions.
 */
void cryptocell_disable(void);

#endif /* CRYPTOCELL_UTIL */