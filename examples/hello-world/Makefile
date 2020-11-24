# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

FEATURES_REQUIRED += periph_hwcrypto


ifeq (pba-d-01-kw2x, $(BOARD))
	USEMODULE += crypto_aes
	USEMODULE += hashes
	USEMODULE += lib_mmcau
endif

ifeq (1, $(TEST_MEM))
	CFLAGS += -DTEST_MEM=1
endif

ifeq (1, $(TEST_STACK))
	USEMODULE += ps
	CFLAGS += -DDEVELHELP=1
	CFLAGS += -DTEST_STACK=1
else
	FEATURES_REQUIRED += periph_gpio
endif

ifeq (1, $(USE_TIMER))
	USEMODULE += xtimer
	CFLAGS += -DUSE_TIMER=1
endif

ifeq (1, $(AES_ECB))
	CFLAGS += -DAES_ECB=1
	CFLAGS += -DAES=1
endif

ifeq (1, $(AES_CBC))
	CFLAGS += -DAES_CBC=1
	CFLAGS += -DAES=1
endif

ifeq (1, $(SHA256))
	CFLAGS += -DSHA256=1
endif

ifeq (1, $(INPUT_512))
	CFLAGS += -DINPUT_512=1
endif

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
