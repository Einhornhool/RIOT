#include <string.h>
// #include <stdio.h>
int riot_nv_seed_read(unsigned char *buf, size_t buf_len)
{
    // puts("RIOT NV read");
    memset(buf, 0, buf_len);
    return 0;
}

int riot_nv_seed_write(unsigned char *buf, size_t buf_len)
{
    (void) buf;
    (void) buf_len;
    return 0;
}
