BOARD ?= nrf52dk

include ../Makefile.tests_common

#BOARD_WHITELIST := nrf52dk

export IMAGE_VERSION = 1.1.1+1

DISABLE_MODULE += core_idle_thread
DISABLE_MODULE += core_thread
DISABLE_MODULE += core_msg
DISABLE_MODULE += auto_init
DISABLE_MODULE += cortexm_fpu

# this test is supposed to always build the mcuboot image
ifneq ($(BUILD_IN_DOCKER),1)
# HACK: When building with docker, mcuboot target must be done only in docker
all: mcuboot
endif

include $(RIOTBASE)/Makefile.include
