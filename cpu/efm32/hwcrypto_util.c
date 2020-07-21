#include <stdbool.h>
#include "hwcrypto.h"
#include "mutex.h"

static mutex_t hwcrypto_lock[HWCRYPTO_NUMOF];

void hwcrypto_init(hwcrypto_t dev)
{
    assert(dev < HWCRYPTO_NUMOF);

    /* initialize lock */
    mutex_init(&hwcrypto_lock[dev]);
}

void hwcrypto_acquire(hwcrypto_t dev)
{
    mutex_lock(&hwcrypto_lock[dev]);

    CMU_ClockEnable(cmuClock_HFPER, true);
    CMU_ClockEnable(hwcrypto_config[dev].cmu, true);
}

void hwcrypto_release(hwcrypto_t dev)
{
    CMU_ClockEnable(hwcrypto_config[dev].cmu, false);

    mutex_unlock(&hwcrypto_lock[dev]);
}