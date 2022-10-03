/*
 * Linker script for 64-bit vDSO.
 * Copied from Linux kernel arch/powerpc/kernel/vdso/vdso64.lds.S
 *
 * $FreeBSD$
 */

SECTIONS
{
	. = . + SIZEOF_HEADERS;

	.hash		: { *(.hash) }			:text
	.gnu.hash	: { *(.gnu.hash) }
	.dynsym		: { *(.dynsym) }
	.dynstr		: { *(.dynstr) }
	.gnu.version	: { *(.gnu.version) }
	.gnu.version_d	: { *(.gnu.version_d) }
	.gnu.version_r	: { *(.gnu.version_r) }

	.note		: { *(.note.*) }		:text	:note

	. = ALIGN(0x100);
	.text		: {
		*(.text .stub .text.* )
		*(.sfpr .glink)
	}						:text   =0x90909090
	PROVIDE(__etext = .);
	PROVIDE(_etext = .);
	PROVIDE(etext = .);

	/*
	 * Other stuff is appended to the text segment:
	 */
	.rodata		: { *(.rodata .rodata.* .gnu.linkonce.r.*) }
	.rodata1	: { *(.rodata1) }

	.dynamic	: { *(.dynamic) }		:text	:dynamic

	/*.eh_frame_hdr	: { *(.eh_frame_hdr) }		:text	:eh_frame_hdr
	.eh_frame	: { KEEP (*(.eh_frame)) }	:text
	.gcc_except_table : { *(.gcc_except_table) }*/
	.rela.dyn ALIGN(8) : { *(.rela.dyn) }

	.got ALIGN(8)	: { *(.got .toc) }

	_end = .;
	PROVIDE(end = .);

	/* STABS_DEBUG
	DWARF_DEBUG
	ELF_DETAILS */

	/DISCARD/	: {
		*(.note.GNU-stack)
		*(.branch_lt)
		*(.data .data.* .gnu.linkonce.d.* .sdata*)
		*(.bss .sbss .dynbss .dynsbss)
		*(.opd)
	}
}

/*
 * Very old versions of ld do not recognize this name token; use the constant.
 */
/*#define PT_GNU_EH_FRAME	0x6474e550*/

/*
 * We must supply the ELF program headers explicitly to get just one
 * PT_LOAD segment, and set the flags explicitly to make segments read-only.
 */
PHDRS
{
	text		PT_LOAD FILEHDR PHDRS FLAGS(5);	/* PF_R|PF_X */
	dynamic		PT_DYNAMIC FLAGS(4);		/* PF_R */
	note		PT_NOTE FLAGS(4);		/* PF_R */
	/*eh_frame_hdr	PT_GNU_EH_FRAME;*/
}

/*
 * This controls what symbols we export from the DSO.
 */
VERSION
{
	/* LINUX_2.6.15 {
	global:
		__kernel_get_syscall_map;
		__kernel_gettimeofday;
		__kernel_clock_gettime;
		__kernel_clock_getres;
		__kernel_get_tbfreq;
		__kernel_sync_dicache;
		__kernel_sigtramp_rt64;
		__kernel_getcpu;
		__kernel_time;

	local: *;
	}; */

	LINUX_0.0 {
	global:
		linux_vdso_sigcode;
	local: *;
	};
}
