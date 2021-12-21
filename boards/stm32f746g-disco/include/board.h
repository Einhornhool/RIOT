/*
 * Copyright (C) 2021 Inria
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     boards_stm32f746g-disco
 * @{
 *
 * @file
 * @brief       Board specific definitions for the STM32F746G-DISCO
 *
 * @author      Alexandre Abadie <alexandre.abadie@inria.fr>
 */

#ifndef BOARD_H
#define BOARD_H

#include "cpu.h"
#include "periph_conf.h"
#include "periph_cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name    LCD Backlight control defines
 * @{
 */
#define BACKLIGHT_PIN       GPIO_PIN(PORT_K, 3)     /**< Backlight pin */
#define BACKLIGHT_MASK      (1 << 3)                /**< Backlight pin mask */

/** Set the backlight pin */
#define BACKLIGHT_ON        (GPIOK->BSRR = BACKLIGHT_MASK)
/** Clear the backlight pin */
#define BACKLIGHT_OFF       (GPIOK->BSRR = (BACKLIGHT_MASK << 16))
/** Toggle the backlight pin */
#define BACKLIGHT_TOGGLE    (GPIOK->ODR  ^= BACKLIGHT_MASK)
/** @} */

/**
 * @name    LCD display enable pin
 * @{
 */
#define LCD_DISP_PIN        GPIO_PIN(PORT_I, 12)    /**< LCD screen enable pin */
/** @} */

/**
 * @name    LCD screen dimensions
 * @{
 */
#define LCD_SCREEN_WIDTH        480     /**< LCD screen width */
#define LCD_SCREEN_HEIGHT       272     /**< LCD screen height */
/** @} */

/**
 * @name User button
 * @{
 */
#define BTN0_PIN            GPIO_PIN(PORT_I, 11)    /**< BTN0 pin */
#define BTN0_MODE           GPIO_IN                 /**< BTN0 pin mode */
/** @} */

/**
 * @brief   Initialize board specific hardware
 */
void board_init(void);

#ifdef __cplusplus
}
#endif

#endif /* BOARD_H */
/** @} */
