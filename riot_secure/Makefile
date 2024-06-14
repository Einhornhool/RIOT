RIOTBASE ?= $(CURDIR)/..

# name of your application
APPLICATION = riot_secure_image

# If no BOARD is found in the environment, use this default:
BOARD ?= nrf9160dk

USEPKG += cmsis
USEPKG += nrfx

USEMODULE += cortexm_svc

# DISABLE_MODULE += core_idle_thread
# DISABLE_MODULE += core_thread

CFLAGS += -Wno-cast-align
# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
