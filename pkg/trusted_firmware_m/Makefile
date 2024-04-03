PKG_SOURCE_LOCAL=/home/lena/work/repos/trusted-firmware-m
PKG_NAME=trusted_firmware_m
PKG_URL=https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git
# Last commit working
# Problem has something to do with target_cfg.c files of nrf9160 and nrf5340
# being merged afterwards. Didn't care for debugging this (TODO: should be done at some point).
# PKG_VERSION=65d71a3f8b9f1787c0fe19ad25f5b76252f44cdc
PKG_VERSION=ff32fe04626632c69966bea8e673e3797b321211
PKG_LICENSE=BSD-3-Clause

include $(RIOTBASE)/pkg/pkg.mk

.PHONY: all..cmake_version_supported

TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/xcompile-toolchain.cmake

CMAKE_MINIMAL_VERSION = 3.10

CFLAGS += -Wno-unused-parameter

# env -u CC -u CFLAGS
# 1. build source files
# 2. remove TF-M runtime library implementations from tf-m archives to only link toolchain
#    implementations (SPRTL implementations access secure RAM and run into securefault)
#    Workaround, since toolchain implementation does not fulfill all security requirements
#    Alternative fix needed
# 3. Copy all tf-m archive files to tfm_archive folder for linker to find
all: build_api_ns
# env -u CC -u CFLAGS \
#
# "$(MAKE)" -C $(PKG_BUILD_DIR)/api_ns -f $(RIOTBASE)/Makefile.base MODULE=libapi_ns

build_spe: $(PKG_BUILD_DIR)/Makefile
	cmake --build $(PKG_BUILD_DIR) -- install

$(PKG_BUILD_DIR)/Makefile:
	cmake \
			-S$(PKG_SOURCE_DIR) \
			-B$(PKG_BUILD_DIR) \
			-DTFM_PLATFORM=nordic_nrf/nrf9160dk_nrf9160 \
			-DTFM_TOOLCHAIN_FILE=$(PKG_SOURCE_DIR)/toolchain_GNUARM.cmake \
			-DCMAKE_BUILD_TYPE=Debug \
			-DTFM_PROFILE=profile_medium \
			-DPLATFORM_DEFAULT_IMAGE_SIGNING=OFF \
			-DCONFIG_TFM_FLOAT_ABI=hard \
			-DCMAKE_C_COMPILER=/home/lena/apps/arm-gnu-toolchain-12.3.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc

build_api_ns: build_spe
	cmake \
		-B $(PKG_BUILD_DIR)/build_ns \
		-DCONFIG_SPE_PATH=$(PKG_BUILD_DIR)/api_ns \
		-DCMAKE_TOOLCHAIN_FILE=$(TOOLCHAIN_FILE) \
    -DCMAKE_BUILD_TYPE=Debug \
		-DTFM_TOOLCHAIN_FILE=$(PKG_BUILD_DIR)/api_ns/cmake/toolchain_ns_GNUARM.cmake \
		-DCMAKE_C_COMPILER=/home/lena/apps/arm-gnu-toolchain-12.3.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-gcc
	cmake --build $(PKG_BUILD_DIR)/build_ns
	cp $(PKG_BUILD_DIR)/build_ns/libtfm_ns.a $(BINDIR)/libapi_ns.a
	cp $(PKG_BUILD_DIR)/build_ns/spe/platform/libplatform_ns.a $(BINDIR)/libplatform_ns.a

# "$(MAKE)" -C $(PKG_BUILD_DIR)/api_ns/interface/src -f $(RIOTBASE)/Makefile.base MODULE=api_ns

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
