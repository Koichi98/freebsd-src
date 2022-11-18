/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2018 Turing Robotic Industries Inc.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/elf.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/imgact_elf.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/stddef.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_param.h>

#include <powerpc/linux/linux.h>
#include <powerpc/linux/linux_proto.h>
#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_ioctl.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux_vdso.h>

#include <powerpc/linux/linux_sigframe.h>

#include <machine/md_var.h>

#ifdef VFP
#include <machine/vfp.h>
#endif

MODULE_VERSION(linux64elf, 1);


extern struct sysent linux_sysent[LINUX_SYS_MAXSYSCALL];


static int	linux_copyout_strings(struct image_params *imgp,
		    uintptr_t *stack_base);
static int	linux_elf_fixup(uintptr_t *stack_base,
		    struct image_params *iparams);
static bool	linux_trans_osrel(const Elf_Note *note, int32_t *osrel);
static void	linux_set_syscall_retval(struct thread *td, int error);
static int	linux_fetch_syscall_args(struct thread *td);
static void	linux_exec_setregs(struct thread *td, struct image_params *imgp,
		    uintptr_t stack);


static int
linux_fetch_syscall_args(struct thread *td)
{
	struct proc *p;
	struct syscall_args *sa;
	struct trapframe *frame;
	register_t *ap;

	p = td->td_proc;
	frame = td->td_frame;
	sa = &td->td_sa;

	sa->args[0] = frame->fixreg[LINUX_FIRSTARG];
	sa->args[1] = frame->fixreg[LINUX_FIRSTARG+1];
	sa->args[2] = frame->fixreg[LINUX_FIRSTARG+2];
	sa->args[3] = frame->fixreg[LINUX_FIRSTARG+3];
	sa->args[4] = frame->fixreg[LINUX_FIRSTARG+4];
	sa->args[5] = frame->fixreg[LINUX_FIRSTARG+5];

	sa->code = frame->fixreg[0];
	sa->original_code = sa->code;

	// What to do with cr registers?

	if (sa->code >= p->p_sysent->sv_size)
		sa->callp = &p->p_sysent->sv_table[0];
	else
		sa->callp = &p->p_sysent->sv_table[sa->code];

	td->td_retval[0] = 0;
	td->td_retval[1] = frame->fixreg[LINUX_FIRSTARG+1];

	return (0);
}

static void
linux_set_syscall_retval(struct thread *td, int error)
{

	// Copied from cpu_set_syscall_retval():/sys/powerpc/powerpc/exec_machdep.c
	if (tf->fixreg[0] == SYS___syscall &&
		(SV_PROC_FLAG(p, SV_ILP32))) {
		int code = tf->fixreg[FIRSTARG + 1];
		fixup = (
#if defined(COMPAT_FREEBSD6) && defined(SYS_freebsd6_lseek)
		    code != SYS_freebsd6_lseek &&
#endif
		    code != SYS_lseek) ?  1 : 0;
	} else
		fixup = 0;

	if (fixup) {
		/*
			* 64-bit return, 32-bit syscall. Fixup byte order
			*/
		tf->fixreg[LINUX_FIRSTARG] = 0;
		tf->fixreg[LINUX_FIRSTARG + 1] = td->td_retval[0];
	} else {
		tf->fixreg[LINUX_FIRSTARG] = td->td_retval[0];
		tf->fixreg[LINUX_FIRSTARG + 1] = td->td_retval[1];
	}
	cpu_set_syscall_retval(td, error);

	if (__predict_false(error != 0)) {
		// Not sure why only for ERESTART and EJUSTRETURN
		if (error != ERESTART && error != EJUSTRETURN)
			td->td_frame->fixreg[FIRSTARG] = bsd_to_linux_errno(error);
	}
}

static int
linux_copyout_auxargs(struct image_params *imgp, uintptr_t base)
{
	Elf_Auxargs *args;
	Elf_Auxinfo *argarray, *pos;
	struct proc *p;
	int error, issetugid;

	LIN_SDT_PROBE0(sysvec, linux_copyout_auxargs, todo);
	p = imgp->proc;

	args = (Elf64_Auxargs *)imgp->auxargs;
	argarray = pos = malloc(LINUX_AT_COUNT * sizeof(*pos), M_TEMP,
	    M_WAITOK | M_ZERO);

	issetugid = p->p_flag & P_SUGID ? 1 : 0;
	// TODO
	//AUXARGS_ENTRY(pos, LINUX_AT_SYSINFO_EHDR, linux_vdso_base);
	AUXARGS_ENTRY(pos, LINUX_AT_MINSIGSTKSZ, LINUX_MINSIGSTKSZ);
	// TODO
	//AUXARGS_ENTRY(pos, LINUX_AT_HWCAP, *imgp->sysent->sv_hwcap);
	AUXARGS_ENTRY(pos, AT_PAGESZ, args->pagesz);
	AUXARGS_ENTRY(pos, LINUX_AT_CLKTCK, stclohz);
	AUXARGS_ENTRY(pos, AT_PHDR, args->phdr);
	AUXARGS_ENTRY(pos, AT_PHENT, args->phent);
	AUXARGS_ENTRY(pos, AT_PHNUM, args->phnum);
	AUXARGS_ENTRY(pos, AT_BASE, args->base);
	AUXARGS_ENTRY(pos, AT_FLAGS, args->flags);
	AUXARGS_ENTRY(pos, AT_ENTRY, args->entry);
	AUXARGS_ENTRY(pos, AT_UID, imgp->proc->p_ucred->cr_ruid);
	AUXARGS_ENTRY(pos, AT_EUID, imgp->proc->p_ucred->cr_svuid);
	AUXARGS_ENTRY(pos, AT_GID, imgp->proc->p_ucred->cr_rgid);
	AUXARGS_ENTRY(pos, AT_EGID, imgp->proc->p_ucred->cr_svgid);
	AUXARGS_ENTRY(pos, LINUX_AT_SECURE, issetugid);
	AUXARGS_ENTRY_PTR(pos, LINUX_AT_RANDOM, imgp->canary);
	//AUXARGS_ENTRY(pos, LINUX_AT_HWCAP2, *imgp->sysent->sv_hwcap2);
	if (imgp->execpathp != 0)
		AUXARGS_ENTRY_PTR(pos, LINUX_AT_EXECFN, imgp->execpathp);
	if (args->execfd != -1)
		AUXARGS_ENTRY(pos, AT_EXECFD, args->execfd);
	// TODO
	//AUXARGS_ENTRY(pos, LINUX_AT_PLATFORM, PTROUT(linux_platform));
	AUXARGS_ENTRY(pos, AT_NULL, 0);

	free(imgp->auxargs, M_TEMP);
	imgp->auxargs = NULL;
	KASSERT(pos - argarray <= LINUX_AT_COUNT, ("Too many auxargs"));

	error = copyout(argarray, (void *)base,
	    sizeof(*argarray) * LINUX_AT_COUNT);
	free(argarray, M_TEMP);
	return (error);
}


/*
 * Copy strings out to the new process address space, constructing new arg
 * and env vector tables. Return a pointer to the base so that it can be used
 * as the initial stack pointer.
 * LINUXTODO: deduplicate against other linuxulator archs
 */
static int
linux_copyout_strings(struct image_params *imgp, uintptr_t *stack_base)
{
	char **vectp;　
	char *stringp;
	uintptr_t destp, ustringp;
	struct ps_strings *arginfo;
	char canary[LINUX_AT_RANDOM_LEN];
	size_t execpath_len;
	struct proc *p;
	int argc, envc, error;

	p = imgp->proc;
	arginfo = (struct ps_strings *)PROC_PS_STRINGS(p);
	destp = (uintptr_t)arginfo;

	if (imgp->execpath != NULL && imgp->auxargs != NULL) {
		execpath_len = strlen(imgp->execpath) + 1;
		destp -= execpath_len;
		destp = rounddown2(destp, sizeof(void *));
		imgp->execpathp = (void *)destp;
		error = copyout(imgp->execpath, imgp->execpathp, execpath_len);
		if (error != 0)
			return (error);
	}

	/* Prepare the canary for SSP. */
	arc4rand(canary, sizeof(canary), 0);
	destp -= roundup(sizeof(canary), sizeof(void *));
	imgp->canary = (void *)destp;
	error = copyout(canary, imgp->canary, sizeof(canary));
	if (error != 0)
		return (error);

	/* Allocate room for the argument and environment strings. */
	destp -= ARG_MAX - imgp->args->stringspace;
	destp = rounddown2(destp, sizeof(void *));
	ustringp = destp;

	if (imgp->auxargs) {
		/*
		 * Allocate room on the stack for the ELF auxargs
		 * array.  It has up to LINUX_AT_COUNT entries.
		 */
		destp -= LINUX_AT_COUNT * sizeof(Elf64_Auxinfo);
		destp = rounddown2(destp, sizeof(void *));
	}

	vectp = (char **)destp;

	/*
	 * Allocate room for argc and the argv[] and env vectors including the
	 * terminating NULL pointers.
	 */
	vectp -= 1 + imgp->args->argc + 1 + imgp->args->envc + 1;

	/*  NOT SURE WITH THIS
	 * Starting with 2.24, glibc depends on a 16-byte stack alignment.
	 * One "long argc" will be prepended later.
	 */
	vectp = (char **)((((uintptr_t)vectp + 8) & ~0xF) - 8);

	/* vectp also becomes our initial stack base. */
	*stack_base = (uintptr_t)vectp;

	stringp = imgp->args->begin_argv;
	argc = imgp->args->argc;
	envc = imgp->args->envc;

	/* Copy out strings - arguments and environment. */
	error = copyout(stringp, (void *)ustringp,
	    ARG_MAX - imgp->args->stringspace);
	if (error != 0)
		return (error);

	/* Fill in "ps_strings" struct for ps, w, etc. */
	if (suword(&arginfo->ps_argvstr, (long)(intptr_t)vectp) != 0 ||
	    suword(&arginfo->ps_nargvstr, argc) != 0)
		return (EFAULT);

	////  Do we really need this? (amd64 doesn't have this. <- Done in linux_fixup_elf)
	//if (suword(vectp++, argc) != 0)
		//return (EFAULT);

	/* Fill in argument portion of vector table. */
	for (; argc > 0; --argc) {
		if (suword(vectp++, ustringp) != 0)
			return (EFAULT);
		while (*stringp++ != 0)
			ustringp++;
		ustringp++;
	}

	/* A null vector table pointer separates the argp's from the envp's. */
	if (suword(vectp++, 0) != 0)
		return (EFAULT);

	if (suword(&arginfo->ps_envstr, (long)(intptr_t)vectp) != 0 ||
	    suword(&arginfo->ps_nenvstr, envc) != 0)
		return (EFAULT);

	/* Fill in environment portion of vector table. */
	for (; envc > 0; --envc) {
		if (suword(vectp++, ustringp) != 0)
			return (EFAULT);
		while (*stringp++ != 0)
			ustringp++;
		ustringp++;
	}

	/* The end of the vector table is a null pointer. */
	if (suword(vectp, 0) != 0)
		return (EFAULT);

	if (imgp->auxargs) {
		vectp++;
		error = imgp->sysent->sv_copyout_auxargs(imgp,
		    (uintptr_t)vectp);
		if (error != 0)
			return (error);
	}

	return (0);
}

/*
 * Reset registers to default values on exec.
 */
static void
linux_exec_setregs(struct thread *td, struct image_params *imgp,
    uintptr_t stack)
{
	struct trapframe	*tf;
	register_t		argc;

	tf = trapframe(td);
	bzero(tf, sizeof *tf);
	#ifdef __powerpc64__
	tf->fixreg[1] = -roundup(-stack + 48, 16);
	#else
	tf->fixreg[1] = -roundup(-stack + 8, 16);
	#endif

	/*
	 * Set up arguments for _start():
	 *	_start(argc, argv, envp, obj, cleanup, ps_strings);
	 *
	 * Notes:
	 *	- obj and cleanup are the auxilliary and termination
	 *	  vectors.  They are fixed up by ld.elf_so.
	 *	- ps_strings is a NetBSD extention, and will be
	 * 	  ignored by executables which are strictly
	 *	  compliant with the SVR4 ABI.
	 */

	/* Collect argc from the user stack */
	argc = fuword((void *)stack);

	tf->fixreg[3] = argc;
	tf->fixreg[4] = stack + sizeof(register_t);
	tf->fixreg[5] = stack + (2 + argc)*sizeof(register_t);
	tf->fixreg[6] = 0;				/* auxillary vector */
	tf->fixreg[7] = 0;				/* termination vector */
	tf->fixreg[8] = (register_t)imgp->ps_strings;	/* NetBSD extension */

	tf->srr0 = imgp->entry_addr;
	#ifdef __powerpc64__
	tf->fixreg[12] = imgp->entry_addr;
	#endif
	tf->srr1 = psl_userset | PSL_FE_DFLT;
	cleanup_power_extras(td);
	td->td_pcb->pcb_flags = 0;


}

struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX_SYS_MAXSYSCALL,
	.sv_table	= linux_sysent,
	.sv_fixup	= linux_elf_fixup,
	.sv_sendsig	= NULL,
	.sv_sigcode	= NULL,
	.sv_szsigcode	= NULL,
	.sv_name	= "Linux ELF64",
	.sv_coredump	= elf64_coredump,
	.sv_elf_core_osabi = ELFOSABI_NONE,
	.sv_elf_core_abi_vendor = LINUX_ABI_VENDOR,
	.sv_elf_core_prepare_notes = linux64_prepare_notes,
	.sv_imgact_try	= linux_exec_imgact_try,
	.sv_minsigstksz	= NULL,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= NULL,
	.sv_psstrings	= NULL,
	.sv_psstringssz	= sizeof(struct ps_strings),
	.sv_stackprot	= VM_PROT_READ | VM_PROT_WRITE,
	.sv_copyout_auxargs = linux_copyout_auxargs,
	.sv_copyout_strings = linux_copyout_strings,
	.sv_setregs	= linux_exec_setregs,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_LINUX | SV_LP64 | SV_SHP | SV_SIG_DISCIGN |
	    SV_SIG_WAITNDQ | SV_TIMEKEEP,
	.sv_set_syscall_retval = linux_set_syscall_retval,
	.sv_fetch_syscall_args = linux_fetch_syscall_args,
	.sv_syscallnames = NULL,
	.sv_shared_page_base = NULL,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= linux_schedtail,
	.sv_thread_detach = linux_thread_detach,
	.sv_trap	= NULL,
	.sv_hwcap	= NULL,
	.sv_hwcap2	= NULL,
	.sv_onexec	= NULL,
	.sv_onexit	= linux_on_exit,
	.sv_ontdexit	= linux_thread_dtor,
	.sv_setid_allowed = &linux_setid_allowed_query,
};

static char GNU_ABI_VENDOR[] = "GNU";
static int GNU_ABI_LINUX = 0;

/* LINUXTODO: deduplicate */
static bool
linux_trans_osrel(const Elf_Note *note, int32_t *osrel)
{
	const Elf32_Word *desc;
	uintptr_t p;

	p = (uintptr_t)(note + 1);
	p += roundup2(note->n_namesz, sizeof(Elf32_Addr));

	desc = (const Elf32_Word *)p;
	if (desc[0] != GNU_ABI_LINUX)
		return (false);

	/*
	 * For Linux we encode osrel using the Linux convention of
	 * 	(version << 16) | (major << 8) | (minor)
	 * See macro in linux_mib.h
	 */
	*osrel = LINUX_KERNVER(desc[1], desc[2], desc[3]);
	
	return (true);
}

static Elf_Brandnote linux64_brandnote = {
	.hdr.n_namesz	= sizeof(GNU_ABI_VENDOR),
	.hdr.n_descsz	= 16,
	.hdr.n_type	= 1,
	.vendor		= GNU_ABI_VENDOR,
	.flags		= BN_TRANSLATE_OSREL,
	.trans_osrel	= linux_trans_osrel
};

static Elf64_Brandinfo linux_glibc2brand = {
	.brand		= ELFOSABI_LINUX,
	.machine	= EM_PPC64,
	.compat_3_brand	= "Linux",
	.emul_path	= linux_emul_path,
	.interp_path	= "/lib64/ld-linux-x86-64.so.2",
	.sysvec		= &elf_linux_sysvec,
	.interp_newpath	= NULL,
	.brand_note	= &linux64_brandnote,
	.flags		= BI_CAN_EXEC_DYN | BI_BRAND_NOTE
};

Elf64_Brandinfo *linux_brandlist[] = {
	&linux_glibc2brand,
	NULL
};

static int
linux64_elf_modevent(module_t mod, int type, void *data)
{
	Elf64_Brandinfo **brandinfo;
	struct linux_ioctl_handler**lihp;
	int error;

	error = 0;
	switch(type) {
	case MOD_LOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		    ++brandinfo)
			if (elf64_insert_brand_entry(*brandinfo) < 0)
				error = EINVAL;
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_register_handler(*lihp);
			stclohz = (stathz ? stathz : hz);
			if (bootverbose)
				printf("Linux powerpc64 ELF exec handler installed\n");
		}
		break;
	case MOD_UNLOAD:
		for (brandinfo = &linux_brandlist[0]; *brandinfo != NULL;
		    ++brandinfo)
			if (elf64_brand_inuse(*brandinfo))
				error = EBUSY;
		if (error == 0) {
			for (brandinfo = &linux_brandlist[0];
			    *brandinfo != NULL; ++brandinfo)
				if (elf64_remove_brand_entry(*brandinfo) < 0)
					error = EINVAL;
		}
		if (error == 0) {
			SET_FOREACH(lihp, linux_ioctl_handler_set)
				linux_ioctl_unregister_handler(*lihp);
			if (bootverbose)
				printf("Linux arm64 ELF exec handler removed\n");
		} else
			printf("Could not deinstall Linux arm64 ELF interpreter entry\n");
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (error);
}

static moduledata_t linux64_elf_mod = {
	"linux64elf",
	linux64_elf_modevent,
	0
};

DECLARE_MODULE_TIED(linux64elf, linux64_elf_mod, SI_SUB_EXEC, SI_ORDER_ANY);
MODULE_DEPEND(linux64elf, linux_common, 1, 1, 1);
FEATURE(linux64, "Powerpc64 Linux 64bit support");
