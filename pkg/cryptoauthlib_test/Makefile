PKG_NAME=cryptoauthlib_test
#PKG_URL=https://github.com/MicrochipTech/cryptoauthlib
PKG_SOURCE_LOCAL=~/riot/cryptoauthlib
#PKG_VERSION=af8187776cd3f3faf8bed412eaf6ff7221862e19
#PKG_VERSION=90591bb6de3702d5eab37b9d147608450a586a24
PKG_LICENSE=BSD-3-Clause
PKG_BUILDDIR ?= $(PKGDIRBASE)/$(PKG_NAME)

.PHONY: all..cmake_version_supported

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

include $(RIOTBASE)/pkg/pkg.mk