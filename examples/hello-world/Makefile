# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# CFLAGS += -DTHREAD_STACKSIZE_MAIN=20480

ifeq (1, $(RUN_TFM))
  USEPKG += trusted_firmware_m
  DISABLE_MODULE += core_idle_thread
  DISABLE_MODULE += core_thread
else
  USEMODULE += psa_crypto
  USEMODULE += psa_hash
  USEMODULE += psa_hash_sha_256
  USEMODULE += psa_asymmetric
  USEMODULE += psa_asymmetric_ecc_p256r1
endif

include $(RIOTBASE)/Makefile.include
