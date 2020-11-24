# define the module that is build
MODULE = cpu

# add a list of subdirectories that should also be built
DIRS = periph $(RIOTCPU)/cortexm_common

ARCHIVES += $(RIOTBASE)/cpu/kinetis/mmcau_lib/lib_mmcau.a
USEMODULE += mmcau_lib

# (file triggers compiler bug. see https://github.com/RIOT-OS/RIOT/issues/5775)
SRC_NOLTO += vectors.c

include $(RIOTBASE)/Makefile.base
