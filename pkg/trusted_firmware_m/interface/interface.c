#include <stdio.h>
#include "tfm_ns_interface.h"
#include "common.h"

int32_t tfm_ns_interface_dispatch(veneer_fn fn,
                                  uint32_t arg0, uint32_t arg1,
                                  uint32_t arg2, uint32_t arg3)
{
    (void) fn;
    (void) arg0;
    (void) arg1;
    (void) arg2;
    (void) arg3;
    puts("TFM NS Interface Dispatch");
    return -1;
}

uint32_t tfm_ns_interface_init(void)
{
    puts("TFM NS Interface Init");
    return OS_WRAPPER_ERROR;
}
