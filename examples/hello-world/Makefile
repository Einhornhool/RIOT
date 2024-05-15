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

DISABLE_MODULE += core_idle_thread
DISABLE_MODULE += core_thread

USEMODULE += ztimer_sec
CFLAGS += -DITERATIONS=1000

ifeq (1, $(RUN_TFM))
  USEPKG += trusted_firmware_m
else
  USEPKG += mbedtls
  # USEMODULE += mbedtls_entropy
  # USEMODULE += entropy_source_zero_entropy
  # CFLAGS += -DCONFIG_ENTROPY_SOURCE_ADC_HMIN=65536
  # USEMODULE += psa_crypto
  # USEMODULE += psa_hash
  # USEMODULE += psa_hash_sha_256
  # USEMODULE += psa_asymmetric
  # USEMODULE += psa_asymmetric_ecc_p256r1
endif

ifeq (1, $(TEST_ECDSA))
  CFLAGS += -DTEST_ECDSA
endif

ifeq (1, $(TEST_ECDH))
  CFLAGS += -DTEST_ECDH
endif

ifeq (1, $(TEST_HASH))
  CFLAGS += -DTEST_HASH
endif

ifeq (1, $(TEST_RANDOM))
  CFLAGS += -DTEST_RANDOM
endif

include $(RIOTBASE)/Makefile.include
