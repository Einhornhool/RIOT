# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# USEMODULE += lib_mmcau
# CFLAGS=-DFREESCALE_MMCAU

INCLUDES += -I$(RIOTBASE)/examples/hello-world/includes-nrf
BASELIBS += ./libnrf_cc310_0.9.12.a
CFLAGS+=-DARM_CRYPTOCELL -DMODULE_CORTEXM_COMMON

# BASELIBS += ./lib_mmcau.a
# USEPKG += tinycrypt
CFLAGS += -DCRYPTO_AES -Wno-unused-function

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
