BASE_MODULE := hashes

ifneq (,$(filter psa_riot_hashes_%,$(USEMODULE)))
  # enable submodules
  SUBMODULES := 1
  DIRS += psa_riot_hashes
endif

include $(RIOTBASE)/Makefile.base
