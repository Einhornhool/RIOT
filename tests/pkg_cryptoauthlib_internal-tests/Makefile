include ../Makefile.tests_common

FEATURES_REQUIRED += periph_i2c
CFLAGS += -std=gnu11 -O3 -Wno-unused-parameter -Wno-missing-field-initializers -Wno-int-conversion -Wno-unused-function -Wno-unused-variable -DATCA_HAL_I2C 
CFLAGS += -DDO_NOT_TEST_CERT
USEPKG += cryptoauthlib_test
USEMODULE += xtimer

include $(RIOTBASE)/Makefile.include