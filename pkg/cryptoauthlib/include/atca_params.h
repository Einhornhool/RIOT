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
 * @name    Set default configuration parameters for the ATCA device
 * @ingroup  config
 * @{
 */
#ifndef ATCA_PARAM_I2C
#define ATCA_PARAM_I2C           I2C_DEV(0)
#endif
#ifndef ATCA_PARAM_ADDR
#define ATCA_PARAM_ADR          (ATCA_I2C_ADR)
#endif

#ifndef ATCA_PARAMS
#define ATCA_PARAMS                { .i2c  = ATCA_PARAM_I2C,  \
                                     .addr = ATCA_PARAM_ADR }
#endif

/**@}*/

/**
 * @brief   Allocation of ATCA configuration
 */
static const atca_params_t atca_params[] =
{
    ATCA_PARAMS
};

#ifdef __cplusplus
}
#endif

#endif /* ATCA_PARAMS_H */
/** @} */