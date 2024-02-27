/* Code copied from Zephyr secure_entry_functions.ld */

/* The ARM SAU requires regions to be 32-byte-aligned. */
#define NSC_ALIGN . = ALIGN(32)
#define NSC_ALIGN_END . = ALIGN(32)

#undef SECTION_PROLOGUE
#define SECTION_PROLOGUE(name, options, align) \
        name options : ALIGN_WITH_INPUT align

SECTION_PROLOGUE(.gnu.sgstubs,,)
{
	NSC_ALIGN;
	__sg_start = .;
	/* No input section necessary, since the Secure Entry Veneers are
	   automatically placed after the .gnu.sgstubs output section. */
} > rom
__sg_end = .;
__sg_size = __sg_end - __sg_start;
NSC_ALIGN_END;
__nsc_size = . - __sg_start;
