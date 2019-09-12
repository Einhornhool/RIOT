#include <stdio.h>
#include <string.h>

#include "cryptoauthlib.h"
#include "atca_execution.h"

int main(void)
{
    ATCA_STATUS status = 6;
    ATCAPacket packet;

    packet.param1 = INFO_MODE_REVISION;
    status = atca_execute_command(&packet, _gDevice);

    printf("%d\n", status);
    return 0;
}