/*
 * Copyright (C) 2016 Oliver Hahm <oliver.hahm@inria.fr>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/* This code is public-domain - it is based on libcrypt
 * placed in the public domain by Wei Dai and other contributors.
 */

/**
 * @ingroup     sys_hashes_sha1

 * @{
 *
 * @file
 * @brief       Setup function neccessary to enable ARM CryptoCell module
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 */

#include <stdio.h>
#include "vendor/nrf52840.h"
#include "cryptocell_incl/sns_silib.h"

CRYS_RND_WorkBuff_t*  rndWorkBuff_ptr;
CRYS_RND_State_t*     rndState_ptr;

#if defined(__CC_ARM)
CRYS_RND_State_t   	 rndState = {0};
CRYS_RND_WorkBuff_t  rndWorkBuff = {0};
#else
CRYS_RND_State_t   	 rndState;
CRYS_RND_WorkBuff_t  rndWorkBuff;
#endif

extern void CRYPTOCELL_IRQHandler(void);
void isr_cryptocell(void)
{
    CRYPTOCELL_IRQHandler();
}

void cryptocell_setup(void)
{
    int ret = 0;
    rndState_ptr = &rndState;
    rndWorkBuff_ptr = &rndWorkBuff;

    NVIC_EnableIRQ(CRYPTOCELL_IRQn);

    NRF_CRYPTOCELL->ENABLE = 1;

    ret = SaSi_LibInit();
    if (ret != SA_SILIB_RET_OK) {
        printf("SaSi_LibInit failed: 0x%x\n", ret);
    }

    ret = CRYS_RndInit(rndState_ptr, rndWorkBuff_ptr);
    if (ret != SA_SILIB_RET_OK) {
        printf("CRYS_RndInit failed: 0x%x\n", ret);
    }
}

void cryptocell_finish(void)
{
    int ret = 0;
    SaSi_LibFini();

    ret = CRYS_RND_UnInstantiation(rndState_ptr);
    if (ret != SA_SILIB_RET_OK) {
        printf("CRYS_RND_UnInstatiation failed: 0x%x\n", ret);
    }
}