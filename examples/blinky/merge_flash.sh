#!/bin/zsh

mergehex -m bin/nrf9160dk-ns/blinky.elf ../../riot_secure/bin/nrf9160dk/riot_secure_image.elf -o merged_blinky.hex

arm-none-eabi-objcopy -I ihex -O binary merged_blinky.hex merged_blinky.bin

nrfjprog -f nrf91 --program merged_blinky.hex --sectorerase --verify --reset
