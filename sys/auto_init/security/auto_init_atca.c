

/**
 * @ingroup     sys_auto_init
 * @{
 * @file
 * @brief       Initializes cryptoauth devices
 *
 * @author      >
 * @}
 */

#ifdef MODULE_CRYPTOAUTHLIB
#include "atca.h"
#include "atca_params.h"

#define ENABLE_DEBUG                (0)
#include "debug.h"

#define ATCA_NUMOF (ARRAY_SIZE(atca_params))

/**
 * @brief   Allocate memory for the device descriptors
 */
static atca_t atca_devs[ATCA_NUMOF];

void auto_init_atca(void) {
        for (unsigned i = 0; i < ATCA_NUMOF; i++)
        {
                hal_i2c_init(((void*) &atca_devs[i]), ((ATCAIfaceCfg*) &atca_params[i]));
        }
}
#else
typedef int dont_be_pedantic;
#endif
