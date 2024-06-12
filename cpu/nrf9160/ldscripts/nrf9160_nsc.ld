/* Linker script to configure memory regions. */

INCLUDE cortexm.ld

_rom_nsc_len = 32;
_rom_nsc_start =_rom_start_addr + _rom_offset + _rom_length - _rom_nsc_len;

MEMORY
{
  rom_nsc (rx) : ORIGIN = _rom_nsc_start, LENGTH = _rom_nsc_len
}

SECTIONS
{
  .gnu.sgstubs : ALIGN (32)
  {
      . = ALIGN(32);
      *(.gnu.sgstubs*)
      . = ALIGN(32);
  } > rom_nsc
}
