# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

CFLAGS += -DWOLFSSL_AES_DIRECT

USEPKG += tinycrypt
USEPKG += wolfssl
USEPKG += cifra
# USEPKG += relic
USEMODULE += xtimer

# USEMODULE += crypto_aes
USEMODULE += crypto_aes_precalculated
USEMODULE += cipher_modes
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_aes

# export RELIC_CONFIG_FLAGS=-DARCH=NONE -DOPSYS=NONE -DQUIET=off -DWORD=32 -DFP_PRIME=255 -DWITH="BN;MD;DV;FP;EP;CP;BC;EC" -DSEED=RIOTRND
# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
