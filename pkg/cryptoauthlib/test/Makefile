MODULE := cryptoauthlib_test
PKG_BUILDDIR ?= $(PKGDIRBASE)/$(PKG_NAME)

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

include $(RIOTBASE)/Makefile.base