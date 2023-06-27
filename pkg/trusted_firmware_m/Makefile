PKG_SOURCE_LOCAL=/home/lena/work/repos/trusted-firmware-m
PKG_NAME=trusted_firmware_m
PKG_URL=https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git
PKG_VERSION=55f3913f83529805ff178bda99224f8207fc7d3d
PKG_LICENSE=BSD-3-Clause

include $(RIOTBASE)/pkg/pkg.mk

.PHONY: all..cmake_version_supported

CMAKE_MINIMAL_VERSION = 3.10

TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/xcompile-toolchain.cmake

all: tfm

tfm: (PKG_BUILD_DIR)/Makefile
	env -u CC -u CFLAGS \
 	$(MAKE) -C $(PKG_BUILD_DIR)

(PKG_BUILD_DIR)/Makefile: $(TOOLCHAIN_FILE)
	env -u CC -u CFLAGS cmake \
			-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
			-H$(PKG_SOURCE_DIR) \
			-B$(PKG_BUILD_DIR) \
			-DTFM_PLATFORM=nordic_nrf/nrf9160dk_nrf9160 \
			-DTFM_TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/toolchain_GNUARM.cmake \
			-DCMAKE_BUILD_TYPE=Debug \
			-DCMAKE_C_COMPILER=/home/lena/apps/gcc-arm-none-eabi-10.3-2021.10/bin/arm-none-eabi-gcc

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
	@rm -rf $(BINDIR)/$(PKG_TEST_NAME).a
