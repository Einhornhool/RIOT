PKG_NAME=cryptoauthlib
#PKG_URL=https://github.com/MicrochipTech/cryptoauthlib
PKG_SOURCE_LOCAL=~/riot/cryptoauthlib
#PKG_VERSION=90591bb6de3702d5eab37b9d147608450a586a24
PKG_LICENSE=BSD-3-Clause

.PHONY: all..cmake_version_supported

CMAKE_MINIMAL_VERSION = 3.6.0

#CFLAGS += -std=gnu11 #-mfloat-abi=softfp
CFLAGS += -Wno-unused-parameter -Wno-type-limits -Wno-implicit-fallthrough -Wno-unused-variable -Wno-strict-aliasing

TOOLCHAIN_FILE=$(PKG_BUILDDIR)/xcompile-toolchain.cmake

all: $(PKG_BUILDDIR)/Makefile
	CFLAGS="$(filter-out -Werror -Werror=old-style-definition -Werror=strict-prototypes -Werror=pedantic -Wpedantic -pedantic -std=gnu99, $(CFLAGS) ) " \
	$(MAKE) -C $(PKG_BUILDDIR)/lib && \
	cp $(PKG_BUILDDIR)/lib/libcryptoauth.a $(BINDIR)/$(PKG_NAME).a

$(PKG_BUILDDIR)/Makefile: $(TOOLCHAIN_FILE)
	cd $(PKG_BUILDDIR)/lib && CC="$(CC)" CXX="$(CXX)" \
	CFLAGS="$(filter-out -Werror -Werror=old-style-definition -Werror=strict-prototypes -Werror=pedantic -Wpedantic -pedantic -std=gnu99, $(CFLAGS) ) " \
	cmake -DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
		  -Wno-dev \
		  -DCFLAGS="$(CFLAGS)" .

$(TOOLCHAIN_FILE): git-download
	$(RIOTTOOLS)/cmake/generate-xcompile-toolchain.sh > $(TOOLCHAIN_FILE)

git-download: | ..cmake_version_supported

..cmake_version_supported:
	@ # Remove '-rcX' from version as they are not well handled
	$(Q)\
	CMAKE_VERSION=$$(cmake --version | sed -n '1 {s/cmake version //;s/-rc.*//;p;}'); \
	$(RIOTTOOLS)/has_minimal_version/has_minimal_version.sh "$${CMAKE_VERSION}" "$(CMAKE_MINIMAL_VERSION)" cmake

clean::
	@rm -rf $(BINDIR)/$(PKG_NAME).a

include $(RIOTBASE)/pkg/pkg.mk