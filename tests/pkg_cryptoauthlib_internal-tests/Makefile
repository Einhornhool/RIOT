include ../Makefile.tests_common

FEATURES_REQUIRED += periph_i2c
CFLAGS += -std=gnu11 -lto -O3 -Wno-unused-parameter -Wno-missing-field-initializers -Wno-int-conversion -Wno-unused-function -Wno-unused-variable -DATCA_HAL_I2C -DRIOT
CFLAGS += -DDO_NOT_TEST_CERT
USEPKG += cryptoauthlib
USEMODULE += xtimer

INCLUDES+= -I$(CURDIR)
INCLUDES+= -I$(CURDIR)/test
INCLUDES+= -I$(CURDIR)/test/jwt
INCLUDES+= -I$(CURDIR)/test/lib
INCLUDES+= -I$(CURDIR)/test/sha-byte-test-vectors
INCLUDES+= -I$(CURDIR)/test/tng
INCLUDES+= -I$(CURDIR)/test/aes_gcm_cavp_vectors
INCLUDES+= -I$(CURDIR)/test/atcacert

# DIRS+= $(CURDIR)/test
# DIRS+= $(CURDIR)/test/jwt
# DIRS+= $(CURDIR)/test/lib
# DIRS+= $(CURDIR)/test/sha-byte-test-vectors
# DIRS+= $(CURDIR)/test/tng

# SRC+= $(CURDIR)/test/*.c
# SRC+= $(CURDIR)/test/jwt/*.c
# SRC+= $(CURDIR)/test/lib/*.c
# SRC+= $(CURDIR)/test/sha-byte-test-vectors/*.c
# SRC+= $(CURDIR)/test/tng/*.c

.PHONY: all

include $(RIOTBASE)/Makefile.include