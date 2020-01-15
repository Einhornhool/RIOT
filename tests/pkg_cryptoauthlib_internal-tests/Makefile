include ../Makefile.tests_common

INCLUDES += -I$(RIOTBASE)/pkg/cryptoauthlib/include
FEATURES_REQUIRED += periph_i2c
CFLAGS += -DDO_NOT_TEST_CERT
USEPKG += cryptoauthlib
USEMODULE += cryptoauthlib_test

include $(RIOTBASE)/Makefile.include
