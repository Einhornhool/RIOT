#include "../../sys/include/checksum/ucrc16.h"
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#define UINT8_BIT_SIZE              (8U)
#define UINT16_BIT_SIZE             (16U)
#define LEFTMOST_BIT_SET(value)     ((value) & 0x8000U)
#define RIGHTMOST_BIT_SET(value)    ((value) & 0x0001U)


uint16_t atCRC(size_t length, const uint8_t *data)
{
    size_t counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;

    for (counter = 0; counter < length; counter++)
    {
        for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
        {
            data_bit = (data[counter] & shift_register) ? 1 : 0;
            crc_bit = crc_register >> 15;
            crc_register <<= 1;
            if (data_bit != crc_bit)
            {
                crc_register ^= polynom;
            }
        }
    }
    return crc_register;
}

uint16_t ucrc16_calc_be(const uint8_t *buf, size_t len, uint16_t poly,
                        uint16_t seed)
{
    assert(buf != NULL);
    for (unsigned c = 0; c < len; c++, buf++) {
        uint32_t tmp = seed ^ (*buf << (UINT16_BIT_SIZE - UINT8_BIT_SIZE));
        for (unsigned i = 0; i < UINT8_BIT_SIZE; i++) {
            tmp = LEFTMOST_BIT_SET(tmp) ? ((tmp << 1) ^ poly) : (tmp << 1);
        }
        seed = tmp & UINT16_MAX;
    }
    return seed;
}

uint16_t ucrc16_calc_le(const uint8_t *buf, size_t len, uint16_t poly,
                        uint16_t seed)
{
    assert(buf != NULL);
    for (unsigned c = 0; c < len; c++, buf++) {
        seed ^= (*buf);
        for (unsigned i = 0; i < UINT8_BIT_SIZE; i++) {
            seed = RIGHTMOST_BIT_SET(seed) ? ((seed >> 1) ^ poly) : (seed >> 1);
        }
    }
    return seed;
}

int main(void)
{
    // uint8_t buf[] = { 0x41, 0xcc };
    uint8_t buf[] = { 0xab, 0xcd };
    // char buf[] = "123456";
    uint16_t resultAtCRC = atCRC(sizeof(buf), buf);

    uint16_t resultUCRCLe = ucrc16_calc_le(buf, sizeof(buf), 0x8005, 0xffff);
    uint16_t resultUCRCBe = ucrc16_calc_be(buf, sizeof(buf), 0x8005, 0xffff);

    printf("atCRC: %x\nuCRC-le: %x\nuCRC-be: %x\n", resultAtCRC, resultUCRCLe, resultUCRCBe );

    return 0;
}