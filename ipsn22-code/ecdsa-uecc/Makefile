# name of the application
APPLICATION = uecc_ecdsa

CFLAGS +=-DDEVELHELP=1
CFLAGS += -DTHREAD_STACKSIZE_MAIN=\(5*THREAD_STACKSIZE_DEFAULT\)

export TEST_KCONFIG ?= 1

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

include $(RIOTBASE)/Makefile.include