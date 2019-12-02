

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

#define ATCADEV_NUMOF (ARRAY_SIZE(atca_params))

/**
 * @brief   Allocate memory for the device descriptors
 */
static atca_t atca_devs[TMP00X_NUM];

void auto_init_atca(void) {
        for (int i = 0; i < ATCADEV_NUMOF; i++)
        {
                atca_init(&atca_devs[i], &atca_params[i]);
        }
    }
}
#else
typedef int dont_be_pedantic;
#endif
