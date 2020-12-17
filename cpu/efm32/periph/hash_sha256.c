/*
 * Copyright (C) 2020 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_hashes

 * @{
 *
 * @file
 * @brief       Implementation of hardware accelerated SHA256 operation
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <string.h>
#include <assert.h>
#include "em_crypto.h"
#include "em_core.h"
#include "crypto_util.h"
#include "hashes/sha256.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

void sha2xx_transform(uint32_t* state, const unsigned char* block)
{
    CORE_DECLARE_IRQ_STATE;
    CRYPTO_TypeDef* dev = crypto_acquire();

    /* Write mode to control register of crypto device */
    dev->CTRL = CRYPTO_CTRL_SHA_SHA2;
    /*  Clear Wide Arithmetic Configuration. WAC determines width of operation when performing arithmetic/shift instructions. */
    dev->WAC = 0;
    /* Clear Interrupt Enable Register */
    dev->IEN = 0;

    /* Set result width of MADD32 operation. Write result to WAC*/
    CRYPTO_ResultWidthSet(dev, cryptoResult256Bits);

    /* Clear sequence control registers */
    dev->SEQCTRL  = 0;
    dev->SEQCTRLB = 0;

    CORE_ENTER_CRITICAL();
    CRYPTO_DDataWrite(&dev->DDATA1, state);
    CORE_EXIT_CRITICAL();

    CRYPTO_EXECUTE_3(   dev,
                        CRYPTO_CMD_INSTR_DDATA1TODDATA0,
                        CRYPTO_CMD_INSTR_DDATA1TODDATA2,
                        CRYPTO_CMD_INSTR_SELDDATA0DDATA1 );

    /* Load data block */
    if ((uint32_t)(block) & 0x3) {
        uint32_t temp[SHA256_INTERNAL_BLOCK_SIZE/sizeof(uint32_t)];
        memcpy(temp, block, SHA256_INTERNAL_BLOCK_SIZE);
        CORE_ENTER_CRITICAL();
        CRYPTO_QDataWrite(&dev->QDATA1BIG, temp);
        CORE_EXIT_CRITICAL();
    }
    else {
        CORE_ENTER_CRITICAL();
        CRYPTO_QDataWrite(&dev->QDATA1BIG, (uint32_t*) block);
        CORE_EXIT_CRITICAL();
    }

    CRYPTO_EXECUTE_3(   dev,
                        CRYPTO_CMD_INSTR_SHA,
                        CRYPTO_CMD_INSTR_MADD32,
                        CRYPTO_CMD_INSTR_DDATA0TODDATA1 );

    CORE_ENTER_CRITICAL();
    CRYPTO_DDataRead(&dev->DDATA0, state);
    CORE_EXIT_CRITICAL();

    crypto_release(dev);
}
