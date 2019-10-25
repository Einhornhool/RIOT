/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg
 *
 * @{
 * @file
 * @brief       Default configuration for 
 *
 * @author      
 */

#ifndef ATCA_PARAMS_H
#define ATCA_PARAMS_H

#include "cryptoauthlib.h"
#include "cryptoauthlib_contrib.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name    Set default configuration parameters for the ATCA Package
 * @ingroup  config
 * @{
 */
#ifndef ATCA_PARAM_I2C
#define ATCA_PARAM_I2C           I2C_DEV(0)
#endif
#ifndef ATCA_PARAM_ADDR
#define ATCA_PARAM_ADDR          (ATCA_I2C_ADDRESS)
#endif
#ifndef ATCA_PARAM_RATE
#define ATCA_PARAM_RATE           
#endif

#ifndef ATCA_PARAMS
#define ATCA_PARAMS                { .i2c  = ATCA_PARAM_I2C,  \
                                     .addr = ATCA_PARAM_ADDR, \
                                     .rate = ATCA_PARAM_RATE }
#endif

/**@}*/

/**
 * @brief   ATCA configuration
 */
static const ATCA_params_t ATCA_params[] =
{
    ATCA_PARAMS
};

#ifdef __cplusplus
}
#endif

#endif /* ATCA_PARAMS_H */
/** @} */