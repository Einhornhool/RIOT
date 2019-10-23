/**
* @defgroup     
* @ingroup      pkg
* @brief
* @{
*
* @file
* @brief       Wrapper for Microchip Cryptoauthlib
*
* More detailed information about the file and the functionality implemented.
*
* @author      
*
*/

#ifndef CRYPTOAUTHLIB_CONTRIB_H
#define CRYPTOAUTHLIB_CONTRIB_H

#ifdef __cplusplus
extern "C" {
#endif


/* For ATECC508A*/
/* Default adress shifted by 1, to ignore lsb (rw bit) */
#define DEV_ADR (0xC0 >> 1)

/* Word Address -> data area to read */
#define WORD_ADR (0x03)
#define SLEEP_ADR (0x01)
#define IDLE_ADR (0x02)
#define I2C_DEVICE (I2C_DEV(0))

#ifdef __cplusplus
}
#endif

#endif