/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     cpu_nrf52
 * @{
 *
 * @file
 * @brief       Utility functions to setup and terminate the CryptoCell 310 driver
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#ifndef PERIPH_CRYPTOCELL_SETUP_H
#define PERIPH_CRYPTOCELL_SETUP_H

/**
 * @brief   Enables CryptoCell module, IRQs and crypto libraries on nrf52840.
 *
 *          Must be called once before using the CryptoCell lib.
 */
void cryptocell_setup(void);

/**
 * @brief   Finishes the use of the CryptoCell library.
 *
 *          Should be called after using the CryptoCell lib.
 */
void cryptocell_terminate(void);

#endif /* PERIPH_CRYPTOCELL_SETUP_H */