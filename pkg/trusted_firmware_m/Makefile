PKG_SOURCE_LOCAL=/home/lena/work/repos/trusted-firmware-m
PKG_NAME=trusted_firmware_m
PKG_URL=https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git
# Last commit working
# Problem has something to do with target_cfg.c files of nrf9160 and nrf5340
# being merged afterwards. Didn't care for debugging this (TODO: should be done at some point).
PKG_VERSION=65d71a3f8b9f1787c0fe19ad25f5b76252f44cdc
PKG_LICENSE=BSD-3-Clause

include $(RIOTBASE)/pkg/pkg.mk

.PHONY: all..cmake_version_supported

CMAKE_MINIMAL_VERSION = 3.10

TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/xcompile-toolchain.cmake

# env -u CC -u CFLAGS
all: $(PKG_BUILD_DIR)/Makefile
	$(MAKE) -C $(PKG_BUILD_DIR)
	$(Q)cp $$(find $(PKG_BUILD_DIR)/secure_fw -name "*.a") $(BINDIR)/tfm_archives
	$(Q)cp $$(find $(PKG_BUILD_DIR)/platform -name "*.a") $(BINDIR)/tfm_archives
	$(Q)rm $$(find $(BINDIR)/tfm_archives -name "*bl2*")

# env -u CC -u CFLAGS
$(PKG_BUILD_DIR)/Makefile: $(TOOLCHAIN_FILE)
	$(Q)mkdir -p $(BINDIR)/tfm_archives
	cmake \
			-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
			-S$(PKG_SOURCE_DIR) \
			-B$(PKG_BUILD_DIR) \
			-DTFM_PLATFORM=nordic_nrf/nrf9160dk_nrf9160 \
			-DTFM_TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/toolchain_GNUARM.cmake \
			-DCMAKE_BUILD_TYPE=Debug \
			-DCMAKE_C_COMPILER=/home/lena/apps/gcc-arm-none-eabi-10.3-2021.10/bin/arm-none-eabi-gcc \
      -DTFM_PARTITION_CRYPTO=ON \
      -DTFM_PARTITION_INTERNAL_TRUSTED_STORAGE=ON \
      -DTFM_PSA_API=ON \

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
