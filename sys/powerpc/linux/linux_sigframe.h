/*-
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2022 Dmitry Chagin <dchagin@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _POWERPC_LINUX_SIGFRAME_H_
#define	_POWERPC_LINUX_SIGFRAME_H_


#define LINUX_ELF_NGREG	    48	/* includes nip, msr, lr, etc. */
#define LINUX_ELF_NFPREG	33	/* includes fpscr */
#define LINUX_ELF_NVRREG	34	/* includes vscr & vrsave in split vectors */
#define GP_REGS_SIZE        min(sizeof(l_elf_greg_t64), sizeof(struct l_user_pt_regs))
#define PT_SOFTE            39


typedef unsigned long l_elf_greg_t64;
typedef l_elf_greg_t64 l_elf_gregset_t64[LINUX_ELF_NGREG];
typedef l_elf_gregset_t64 l_elf_gregset_t;

/* Floating point registers */
typedef double l_elf_fpreg_t;
typedef l_elf_fpreg_t l_elf_fpregset_t[LINUX_ELF_NFPREG];

typedef struct {
	unsigned int u[4];
} __attribute__((aligned(16))) l__vector128;

typedef l__vector128 l_elf_vrreg_t;

struct l_user_pt_regs
{
	unsigned long gpr[32];
	unsigned long nip;
	unsigned long msr;
	unsigned long orig_gpr3;	/* Used for restarting system calls */
	unsigned long ctr;
	unsigned long link;
	unsigned long xer;
	unsigned long ccr;
#ifdef __powerpc64__
	unsigned long softe;		/* Soft enabled/disabled */
#else
	unsigned long mq;		/* 601 only (not used at present) */
					/* Used on APUS to hold IPL value. */
#endif
	unsigned long trap;		/* Reason for being here */
	/* N.B. for critical exceptions on 4xx, the dar and dsisr
	   fields are overloaded to hold srr0 and srr1. */
	unsigned long dar;		/* Fault registers */
	unsigned long dsisr;		/* on 4xx/Book-E used for ESR */
	unsigned long result;		/* Result of a system call */
};


struct l_sigcontext {
	unsigned long	_unused[4];
	int		signal;
#ifdef __powerpc64__
	int		_pad0;
#endif
	unsigned long	handler;
	unsigned long	oldmask;
	struct l_user_pt_regs *regs;
#ifdef __powerpc64__
	l_elf_gregset_t	gp_regs;
	l_elf_fpregset_t	fp_regs;
/*
 * To maintain compatibility with current implementations the sigcontext is
 * extended by appending a pointer (v_regs) to a quadword type (elf_vrreg_t)
 * followed by an unstructured (vmx_reserve) field of 101 doublewords. This
 * allows the array of vector registers to be quadword aligned independent of
 * the alignment of the containing sigcontext or ucontext. It is the
 * responsibility of the code setting the sigcontext to set this pointer to
 * either NULL (if this processor does not support the VMX feature) or the
 * address of the first quadword within the allocated (vmx_reserve) area.
 *
 * The pointer (v_regs) of vector type (elf_vrreg_t) is type compatible with
 * an array of 34 quadword entries (elf_vrregset_t).  The entries with
 * indexes 0-31 contain the corresponding vector registers.  The entry with
 * index 32 contains the vscr as the last word (offset 12) within the
 * quadword.  This allows the vscr to be stored as either a quadword (since
 * it must be copied via a vector register to/from storage) or as a word.
 * The entry with index 33 contains the vrsave as the first word (offset 0)
 * within the quadword.
 *
 * Part of the VSX data is stored here also by extending vmx_restore
 * by an additional 32 double words.  Architecturally the layout of
 * the VSR registers and how they overlap on top of the legacy FPR and
 * VR registers is shown below:
 *
 *                    VSR doubleword 0               VSR doubleword 1
 *           ----------------------------------------------------------------
 *   VSR[0]  |             FPR[0]            |                              |
 *           ----------------------------------------------------------------
 *   VSR[1]  |             FPR[1]            |                              |
 *           ----------------------------------------------------------------
 *           |              ...              |                              |
 *           |              ...              |                              |
 *           ----------------------------------------------------------------
 *   VSR[30] |             FPR[30]           |                              |
 *           ----------------------------------------------------------------
 *   VSR[31] |             FPR[31]           |                              |
 *           ----------------------------------------------------------------
 *   VSR[32] |                             VR[0]                            |
 *           ----------------------------------------------------------------
 *   VSR[33] |                             VR[1]                            |
 *           ----------------------------------------------------------------
 *           |                              ...                             |
 *           |                              ...                             |
 *           ----------------------------------------------------------------
 *   VSR[62] |                             VR[30]                           |
 *           ----------------------------------------------------------------
 *   VSR[63] |                             VR[31]                           |
 *           ----------------------------------------------------------------
 *
 * FPR/VSR 0-31 doubleword 0 is stored in fp_regs, and VMX/VSR 32-63
 * is stored at the start of vmx_reserve.  vmx_reserve is extended for
 * backwards compatility to store VSR 0-31 doubleword 1 after the VMX
 * registers and vscr/vrsave.
 */
	l_elf_vrreg_t	*v_regs;
	long		vmx_reserve[LINUX_ELF_NVRREG + LINUX_ELF_NVRREG + 1 + 32];
#endif
}; 

struct l_ucontext {
	unsigned long	uc_flags;
	struct l_ucontext *uc_link;
	l_stack_t	uc_stack;
	l_sigset_t	uc_sigmask;
    l_sigset_t  _unused[15];   /* Allow for uc_sigmask growth */
    struct l_sigcontext uc_mcontext; /* last for extensibility */
};


#define LINUX_TRAMP_TRACEBACK   4
#define LINUX_TRAMP_SIZE        7
#define LINUX_USER_REDZONE_SIZE 512

struct l_rt_sigframe {
    struct l_ucontext uc;
    unsigned long _unused[2];
    unsigned int tramp[LINUX_TRAMP_SIZE];
    l_siginfo_t *pinfo;
    void *puc;
    l_siginfo_t info;
    char abigap[LINUX_USER_REDZONE_SIZE];
} __attribute__((__aligned__(16)));


struct l_sigframe {
	struct l_rt_sigframe sf;
	/* frame_record */
	uint64_t	fp;
	uint64_t	lr;
	ucontext_t	f_uc;
};

#define LINUX__SIGNAL_FRAMESIZE 128

void __kernel_start_sigtramp_rt64(int, void*, void*, void*);


#endif /* _POWERPC_LINUX_SIGFRAME_H_ */
