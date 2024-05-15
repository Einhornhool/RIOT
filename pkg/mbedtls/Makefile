PKG_SOURCE_LOCAL=~/work/repos/mbedtls
PKG_NAME=mbedtls
PKG_URL=https://github.com/ARMmbed/mbedtls.git
# v2.28.0
PKG_VERSION=1ec69067fa1351427f904362c1221b31538c8b57
PKG_LICENSE=Apache-2.0

include $(RIOTBASE)/pkg/pkg.mk

all:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/library \
			  -f $(RIOTBASE)/Makefile.base MODULE=$(PKG_NAME)

