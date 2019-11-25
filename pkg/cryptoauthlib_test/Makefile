PKG_NAME=cryptoauthlib_test
PKG_SOURCE_LOCAL=$(PKGDIRBASE)/cryptoauthlib/test
PKG_LICENSE=BSD-3-Clause
PKG_BUILDDIR ?= $(PKGDIRBASE)/$(PKG_NAME)
TESTINCLDIR = $(PKGDIRBASE)/cryptoauthlib

INCLUDES+= -I$(TESTINCLDIR)
INCLUDES+= -I$(TESTINCLDIR)/test
INCLUDES+= -I$(TESTINCLDIR)/test/jwt
INCLUDES+= -I$(TESTINCLDIR)/test/lib
INCLUDES+= -I$(TESTINCLDIR)/test/sha-byte-test-vectors
INCLUDES+= -I$(TESTINCLDIR)/test/tng
INCLUDES+= -I$(TESTINCLDIR)/test/aes_gcm_cavp_vectors
INCLUDES+= -I$(TESTINCLDIR)/test/atcacert


.PHONY: all..cmake_version_supported

all: patch
	$(info $$CFLAGS is [${CFLAGS}])
	"$(MAKE)" -C $(PKG_BUILDDIR)

patch: git-download
	mkdir -p $(PKG_BUILDDIR)
	cp $(PKG_SOURCE_LOCAL)/*.c $(PKG_BUILDDIR)
	cp $(PKG_SOURCE_LOCAL)/jwt/*.c $(PKG_BUILDDIR)
	# cp $(PKG_SOURCE_LOCAL)/sha-byte-test-vectors/*.c $(PKG_BUILDDIR)
	cp $(PKG_SOURCE_LOCAL)/tng/*.c $(PKG_BUILDDIR)
	# cp $(PKG_SOURCE_LOCAL)/aes_gcm_cavp_vectors/*.c $(PKG_BUILDDIR)
	cp $(PKG_SOURCE_LOCAL)/atcacert/*.c $(PKG_BUILDDIR)

	echo "MODULE = cryptoauthlib_test" > $(PKG_BUILDDIR)/Makefile
	echo "include \$$(RIOTBASE)/Makefile.base" >> $(PKG_BUILDDIR)/Makefile

include $(RIOTBASE)/pkg/pkg.mk