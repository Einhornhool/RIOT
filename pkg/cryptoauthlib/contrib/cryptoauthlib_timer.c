#include "cryptoauthlib.h"
#include "hal/atca_hal.h"

#include "xtimer.h"

void atca_delay_us(uint32_t delay)
{
    xtimer_usleep(delay);
}

void atca_delay_10us(uint32_t delay)
{
    xtimer_usleep(delay * 10);
}

void atca_delay_ms(uint32_t delay)
{
    xtimer_usleep(delay * 1000);
}