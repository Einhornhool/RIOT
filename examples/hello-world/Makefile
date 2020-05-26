NRF_DIR = $(RIOTBASE)/examples/hello-world/nrf-sdk
NRF_COMP_DIR = $(NRF_DIR)/components
# name of your application
APPLICATION = hello-world

# If no BOARD is found in the environment, use this default:
BOARD ?= native

CFLAGS+=-DARM_CRYPTOCELL -DNRF52840_XXAA -Wno-expansion-to-defined -Wno-unused-but-set-variable

# USEPKG += tinycrypt
# CFLAGS += -DAES_TIME
CFLAGS += -DCRYPTO_AES -Wno-unused-function
USEMODULE += nordic_cryptocell
# USEMODULE += lib_mmcau
# CFLAGS=-DFREESCALE_MMCAU
# BASELIBS += ./lib_mmcau.a

ifneq (,$(filter nordic_cryptocell,$(USEMODULE)))
	BASELIBS += $(NRF_DIR)/external/nrf_cc310/lib/cortex-mm4/soft-float/  libnrf_cc310_0.9.12.a

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
	INCLUDES += -I$(NRF_COMP_DIR)/libraries/util
	INCLUDES += -I$(NRF_COMP_DIR)/libraries/mem_manager
	INCLUDES += -I$(NRF_COMP_DIR)/softdevice/s140/headers
	INCLUDES += -I$(NRF_DIR)/modules/nrfx
	INCLUDES += -I$(NRF_DIR)/modules/nrfx/hal
	INCLUDES += -I$(NRF_DIR)/modules/nrfx/drivers/include
	INCLUDES += -I$(NRF_DIR)/modules/nrfx/drivers
	INCLUDES += -I$(NRF_DIR)/modules/nrfx/mdk
	INCLUDES += -I$(NRF_DIR)/modules/nrfx/templates/nRF52840
	INCLUDES += -I$(NRF_DIR)/external/nrf_cc310/include
	INCLUDES += -I$(NRF_DIR)/integration/nrfx
	INCLUDES += -I$(NRF_DIR)/integration/nrfx/legacy

	cp $(NRF_COMP_DIR)/libraries/crypto/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/cc310/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/cc310_bl/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/mbedtls/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/oberon/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/micro_ecc/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/optiga/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/cifra/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/nrf_hw/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/crypto/backend/nrf_sw/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/experimental_section_vars/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/util/*.c $(NRF_DIR)
	cp $(NRF_COMP_DIR)/libraries/mem_manager/*.c $(NRF_DIR)
	cp $(NRF_DIR)/modules/nrfx/hal/*.c $(NRF_DIR)
	cp $(NRF_DIR)/modules/nrfx/drivers/src/*.c $(NRF_DIR)
	cp $(NRF_DIR)/modules/nrfx/mdk/*.c $(NRF_DIR)
	cp $(NRF_DIR)/modules/nrfx/mdk/*.s $(NRF_DIR)
	cp $(NRF_DIR)/integration/nrfx/legacy/*.c $(NRF_DIR)

	echo "MODULE = nordic_cryptocell" > $(NRF_DIR)/Makefile
	echo "include \$$(RIOTBASE)/Makefile.base" >> $(NRF_DIR)/Makefile

	"$(MAKE)" -C $(NRF_DIR)
endif

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
