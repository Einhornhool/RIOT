include ../Makefile.tests_common

FEATURES_REQUIRED += periph_i2c
CFLAGS += -std=gnu11 -Wno-unused-parameter -DATCA_HAL_I2C
USEPKG += cryptoauthlib
USEMODULE += xtimer

.PHONY: all

# $(info $$PKG_BUILDDIR is [${PKG_BUILDDIR}])
# $(info $$BINDIR is [${BINDIR}])
# $(info $$(PKGDIRBASE) is [${$(PKGDIRBASE)}])

# csrc = $(wildcard $(PKGDIRBASE)/)

#all: $(BINDIR)/cryptoauthtest.elf

#$(BINDIR)/cryptoauthtest.elf: 

include $(RIOTBASE)/Makefile.include