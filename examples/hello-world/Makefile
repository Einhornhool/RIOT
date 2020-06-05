NRF_DIR = $(RIOTBASE)/examples/hello-world/nrf-sdk
NRF_COMP_DIR = $(NRF_DIR)/components
# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

CFLAGS+=-DARM_CRYPTOCELL -DNRF52840_XXAA -Wno-expansion-to-defined -Wno-unused-but-set-variable -Wno-unused-parameter

# USEPKG += tinycrypt
# CFLAGS += -DAES_TIME
CFLAGS += -DCRYPTO_AES -Wno-unused-function
# USEMODULE += lib_mmcau
# CFLAGS=-DFREESCALE_MMCAU
# BASELIBS += ./lib_mmcau.a

BASELIBS += ./libnrf5_crypto.a

INCLUDES += -I$(NRF_DIR)/config/nrf52840/config
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/cc310
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/cc310_bl
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/mbedtls
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/oberon
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/micro_ecc
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/optiga
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/cifra
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/nrf_hw
INCLUDES += -I$(NRF_COMP_DIR)/libraries/crypto/backend/nrf_sw
INCLUDES += -I$(NRF_COMP_DIR)/libraries/experimental_section_vars
INCLUDES += -I$(NRF_COMP_DIR)/libraries/log
INCLUDES += -I$(NRF_COMP_DIR)/libraries/log/src
INCLUDES += -I$(NRF_COMP_DIR)/libraries/util
INCLUDES += -I$(NRF_COMP_DIR)/libraries/mem_manager
INCLUDES += -I$(NRF_COMP_DIR)/softdevice/s140/headers
INCLUDES += -I$(NRF_DIR)/modules/nrfx
INCLUDES += -I$(NRF_DIR)/modules/nrfx/hal
INCLUDES += -I$(NRF_DIR)/modules/nrfx/drivers/include
INCLUDES += -I$(NRF_DIR)/modules/nrfx/drivers
INCLUDES += -I$(NRF_DIR)/modules/nrfx/drivers/src
INCLUDES += -I$(NRF_DIR)/modules/nrfx/mdk
INCLUDES += -I$(NRF_DIR)/modules/nrfx/templates/nRF52840
INCLUDES += -I$(NRF_DIR)/external/nrf_cc310/include
INCLUDES += -I$(NRF_DIR)/integration/nrfx
INCLUDES += -I$(NRF_DIR)/integration/nrfx/legacy

nrfsdk:
	cmake \
		-S . \
		-B$(BINDIR) \
		-DCMAKE_C_COMPILER="/home/einhornhool/Downloads/gcc-arm-none-eabi-9-2019-q4-major/bin/arm-none-eabi-gcc" \
		-DCMAKE_TOOLCHAIN_FILE="./cmake/arm-none-eabi.cmake" \
		-DTOOLCHAIN_PREFIX="/home/einhornhool/Downloads/gcc-arm-none-eabi-9-2019-q4-major" \
		-DNRF5_SDK_PATH="$(RIOTBASE)/examples/hello-world/nrf-sdk" \
		-DNRF5_BOARD="pca10056" \
		-DNRF5_SOFTDEVICE_VARIANT="blank" \
		-DNRF5_SDKCONFIG_PATH="$(RIOTBASE)/examples/hello-world"

# BASELIBS += $(NRF_DIR)/external/nrf_cc310/lib/cortex-mm4/soft-float/  libnrf_cc310_0.9.12.a

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
