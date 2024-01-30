ifneq (,$(filter trusted_firmware_m,$(USEPKG)))

# S = Secure, NS = Non-Secure
PKG_BUILD_DIR = $(BINDIR)/pkg-build/trusted_firmware_m
PKG_SOURCE_DIR = $(RIOTBASE)/build/pkg/trusted_firmware_m

BOOTLOADER_IMAGE = $(PKG_BUILD_DIR)/bin/bl2.bin
SECURE_IMAGE = $(PKG_BUILD_DIR)/bin/tfm_s.bin
RIOT_NS_IMAGE = $(BINDIR)/$(APPLICATION).bin
MERGED_BINARY = $(BINDIR)/s_ns_merged_signed.bin

IMAGE_SIGNING_DIR = $(RIOTTOOLS)/trusted_firmware_m/image_signing
IMGTOOL_WRAPPER = $(IMAGE_SIGNING_DIR)/scripts/wrapper/wrapper.py
IMGTOOL ?= $(RIOTTOOLS)/mcuboot/imgtool.py
SIGNING_LAYOUT_S = $(IMAGE_SIGNING_DIR)/layout_files/signing_layout_s.o
SIGNING_LAYOUT_NS = $(IMAGE_SIGNING_DIR)/layout_files/signing_layout_ns.o

SIGNING_KEYFILE_S = $(PKG_SOURCE_DIR)/bl2/ext/mcuboot/root-RSA-3072.pem
SIGNING_KEYFILE_NS = $(PKG_SOURCE_DIR)/bl2/ext/mcuboot/root-RSA-3072_1.pem
# SIGNING_KEYFILE = $(BINDIR)/key.pem

ASSEMBLE_IMAGES = $(IMAGE_SIGNING_DIR)/scripts/assemble.py

$(info $$**************Includes is [${INCLUDES}])
$(info $$**************objects is [${_LINK}])
$(info $$**************link is [${LINK}])
$(info $$**************baselibs is [${BASELIBS}])
$(info $$**************archives is [${ARCHIVES}])
# tfm-create-key: $(SIGNING_KEYFILE)

# ifeq ($(BINDIR)/key.pem,$(SIGNING_KEYFILE))
# $(SIGNING_KEYFILE):
# 	$(Q)mkdir -p $(BINDIR)
# 	$(Q)$(IMGTOOL) keygen -k $@ -t rsa-2048
# endif

# 1. Re-link files with new offset
# 2. Sign secure and non-secure image and merge them into one binary
# This uses the scripts located at dist/tools/trusted_firmware_m.
trusted_firmware_m: ROM_OFFSET=$$(($(MCUBOOT_SLOT0_SIZE) + $(IMAGE_HDR_SIZE)))
trusted_firmware_m: link # tfm-create-key
	$(IMGTOOL_WRAPPER) -v 1.7.0 --layout $(SIGNING_LAYOUT_S) -k $(SIGNING_KEYFILE_S) \
	--public-key-format full --align 1 --pad --pad-header -H $(IMAGE_HDR_SIZE) \
	-s 1 -L 128 $(SECURE_IMAGE) --overwrite-only \
	--measured-boot-record $(BINDIR)/tfm_s_signed.bin && \
	$(IMGTOOL_WRAPPER) -v 1.7.0 --layout $(SIGNING_LAYOUT_NS) -k $(SIGNING_KEYFILE_NS) \
	--public-key-format full --align 1 --pad --pad-header -H $(IMAGE_HDR_SIZE) \
	-s 1 -L 128 $(RIOT_NS_IMAGE) --overwrite-only \
	--measured-boot-record $(BINDIR)/riot_ns_signed.bin && \
	$(ASSEMBLE_IMAGES) --layout $(SIGNING_LAYOUT_S) -s $(BINDIR)/tfm_s_signed.bin \
	-n $(BINDIR)/riot_ns_signed.bin -o $(MERGED_BINARY)

# Flash bootloader first
.PHONY: tfm-flash-bootloader tfm-flash
tfm-flash-bootloader: FLASHFILE = $(BOOTLOADER_IMAGE)
tfm-flash-bootloader: export FLASH_ADDR = 0x0
tfm-flash-bootloader: $(BOOTLOADER_IMAGE) $(FLASHDEPS)
	$(flash-recipe)

# Flash merged binary secong at offset 0x10000
tfm-flash: FLASHFILE = $(MERGED_BINARY)
tfm-flash: export FLASH_ADDR = 0x10000
tfm-flash: trusted_firmware_m $(FLASHDEPS) tfm-flash-bootloader
	$(flash-recipe)

endif
