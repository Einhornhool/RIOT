

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

void auto_init_atca(void) {        
        for (unsigned i = 0; i < ATCA_NUMOF; i++)
        {
                LOG_DEBUG("[auto_init_security] initializing atca device #%u\n", i);
                
                ATCAIfaceCfg cfg = atca_params[i];
                if (atcab_init(&cfg) != ATCA_SUCCESS)
                {
                        LOG_ERROR("[auto_init_security] error initializing atca device #%u\n", i);
                        continue;
                }
        }
}
#else
typedef int dont_be_pedantic;
#endif
