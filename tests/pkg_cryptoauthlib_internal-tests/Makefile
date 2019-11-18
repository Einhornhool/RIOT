include ../Makefile.tests_common

FEATURES_REQUIRED += periph_i2c
CFLAGS += -std=gnu11 -O3 -Wno-unused-parameter -Wno-missing-field-initializers -Wno-int-conversion -Wno-unused-function -Wno-unused-variable -DATCA_HAL_I2C -DRIOT
CFLAGS += -DDO_NOT_TEST_CERT
USEPKG += cryptoauthlib
USEMODULE += xtimer
TESTSRCDIR = $(CURDIR)/bin/pkg/$(BOARD)/cryptoauthlib/test

INCLUDES+= -I$(CURDIR)
INCLUDES+= -I$(TESTSRCDIR)
INCLUDES+= -I$(TESTSRCDIR)/jwt
INCLUDES+= -I$(TESTSRCDIR)/lib
INCLUDES+= -I$(TESTSRCDIR)/sha-byte-test-vectors
INCLUDES+= -I$(TESTSRCDIR)/tng
INCLUDES+= -I$(TESTSRCDIR)/aes_gcm_cavp_vectors
INCLUDES+= -I$(TESTSRCDIR)/atcacert

# USEMODULE += cryptoauthlib_test_global

# SRC += $(wildcard $(TESTSRCDIR)/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/jwt/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/lib/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/sha-byte-test-vectors/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/tng/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/aes_gcm_cavp_vectors/*.c)
# SRC += $(wildcard $(TESTSRCDIR)/atcacert/*.c)

# $(info $$SRC is [${SRC}])

# Lädt Package herunter, sucht alle für die Tests benötigten Dateien zusammen und macht ein Modul daraus ???
all: patch
	"$(MAKE)" -C $(PKG_BUILDDIR)

patch: git-download
	mkdir -p $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/jwt/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/lib/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/sha-byte-test-vectors/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/tng/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/aes_gcm_cavp_vectors/*.c $(PKG_BUILDDIR)
	cp $(TESTSRCDIR)/atcacert/*.c $(PKG_BUILDDIR)

	echo "MODULE = cryptoauthlib_test" > $(PKG_BUILDDIR)/Makefile
	echo "include $$(RIOTBASE)/Makefile.base" >> $(PKG_BUILDDIR)/Makefile

.PHONY: all

include $(RIOTBASE)/Makefile.include