#include <stdint.h>

/* For ATECC508A*/
/* Default adress shifted by 1, to ignore lsb (rw bit) */
#define DEV_ADR (0xC0 >> 1)

/* Word Address -> data area to read */
#define WORD_ADR (0x03)
#define SLEEP_ADR (0x01)
#define IDLE_ADR (0x02)
#define DEVICE (I2C_DEV(0))

/** 
 * @brief This function delays for a number of microseconds.
 *
 * @param[in] delay number of microseconds to delay
 */
void atca_delay_us(uint32_t delay);

/** 
 * @brief This function delays for a number of tens of microseconds.
 *
 * @param[in] delay number of 0.01 milliseconds to delay
 */
void atca_delay_10us(uint32_t delay);

/** 
 * @brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * 
 * @param[in] delay number of milliseconds to delay
 */

void atca_delay_ms(uint32_t delay);

