#include "periph/i2c.h"
#include "atca.h"

#define ENABLE_DEBUG                (0)
#include "debug.h"

int atca_init(atca_t *dev, const ATCAIfaceCfg *params)
{
    dev->params = *params;

    return ATCA_OK;
}