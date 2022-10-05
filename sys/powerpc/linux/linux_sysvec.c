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
#include <powerpc/linux/linux_sigframe.h>
#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_ioctl.h>
#include <compat/linux/linux_mib.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_signal.h>
#include <compat/linux/linux_util.h>
#include <compat/linux/linux_vdso.h>

#include <machine/md_var.h>

#ifdef VFP
#include <machine/vfp.h>
#endif

MODULE_VERSION(linux64elf, 1);

#define	LINUX_VDSOPAGE_SIZE	PAGE_SIZE * 2
#define	LINUX_VDSOPAGE (VM_MAXUSER_ADDRESS - \
				    LINUX_VDSOPAGE_SIZE)
#define	LINUX_SHAREDPAGE	(LINUX_VDSOPAGE - PAGE_SIZE)
				/*
				 * PAGE_SIZE - the size
				 * of the native SHAREDPAGE
				 */
#define	LINUX_USRSTACK LINUX_SHAREDPAGE
#define	LINUX_PS_STRINGS	(LINUX_USRSTACK - \
				    sizeof(struct ps_strings))

static int linux_szsigcode;
static vm_object_t linux_vdso_obj;
static char *linux_vdso_mapping;
//extern char _binary_linux_vdso_so_o_start;
//extern char _binary_linux_vdso_so_o_end;
extern char _binary_linux_locore_o_start;
extern char _binary_linux_locore_o_end;
static vm_offset_t linux_vdso_base;

extern struct sysent linux_sysent[LINUX_SYS_MAXSYSCALL];
uintptr_t aux_vec;

SET_DECLARE(linux_ioctl_handler_set, struct linux_ioctl_handler);

static int	linux_copyout_strings(struct image_params *imgp,
		    uintptr_t *stack_base);
static int	linux_elf_fixup(uintptr_t *stack_base,
		    struct image_params *iparams);
static bool	linux_trans_osrel(const Elf_Note *note, int32_t *osrel);
static void	linux_set_syscall_retval(struct thread *td, int error);
static int	linux_fetch_syscall_args(struct thread *td);
static void	linux_exec_setregs(struct thread *td, struct image_params *imgp,
		    uintptr_t stack);
static void	linux_exec_sysvec_init(void *param);
static int	linux_on_exec_vmspace(struct proc *p,
		    struct image_params *imgp);
static void linux_exec_setregs_funcdesc(struct thread *td, struct image_params *imgp,
    uintptr_t stack);
static void	linux_vdso_install(const void *param);
static void	linux_vdso_deinstall(const void *param);
static void	linux_vdso_reloc(char *mapping, Elf_Addr offset);

static void linux_dump_signal_frame(int *l_rt_sigframe);

LINUX_VDSO_SYM_INTPTR(linux_vdso_sigcode);
LINUX_VDSO_SYM_INTPTR(linux_vdso_rt_sigcode);
LINUX_VDSO_SYM_INTPTR(kern_timekeep_base);

static int
linux_fetch_syscall_args(struct thread *td)
{
	//uprintf(__func__);
	//uprintf("\n");
	struct proc *p;
	struct syscall_args *sa;
	struct trapframe *frame;
	//register_t *ap;

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
	//uprintf("sa->code:%d\n",sa->code);
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

	//uprintf(__func__);
	//uprintf("\n");
	// Refer from cpu_set_syscall_retval():/sys/powerpc/powerpc/exec_machdep.c
	struct trapframe *tf;
	int fixup;

	if (error == EJUSTRETURN)
		return;

	tf = td->td_frame;

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
	//cpu_set_syscall_retval(td, error);

	if (__predict_false(error != 0)) {
		// Not sure why only for ERESTART and EJUSTRETURN
		if (error != ERESTART && error != EJUSTRETURN)
			td->td_frame->fixreg[FIRSTARG] = bsd_to_linux_errno(error);
	}
}

static int
linux_copyout_auxargs(struct image_params *imgp, uintptr_t base)
{
	uprintf(__func__);
	uprintf("\n");
	Elf_Auxargs *args;
	Elf_Auxinfo *argarray, *pos;
	struct proc *p;
	int error, issetugid;

	//LIN_SDT_PROBE0(sysvec, linux_copyout_auxargs, todo);
	p = imgp->proc;

	args = (Elf64_Auxargs *)imgp->auxargs;
	argarray = pos = malloc(LINUX_AT_COUNT * sizeof(*pos), M_TEMP,
	    M_WAITOK | M_ZERO);

	issetugid = p->p_flag & P_SUGID ? 1 : 0;
	// TODO
	//AUXARGS_ENTRY(pos, LINUX_AT_SYSINFO_EHDR, linux_vdso_base);
	//AUXARGS_ENTRY(pos, LINUX_AT_MINSIGSTKSZ, LINUX_MINSIGSTKSZ);
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

static int
linux_elf_fixup(uintptr_t *stack_base, struct image_params *imgp)
{
	Elf_Addr *base;

	base = (Elf64_Addr *)*stack_base;
	base--;
	if (suword(base, (uint64_t)imgp->args->argc) == -1)
		return (EFAULT);

	*stack_base = (uintptr_t)base;
	return (0);
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
	uprintf(__func__);
	uprintf("\n");
	char **vectp;
	char *stringp;
	uintptr_t destp, ustringp;
	struct ps_strings *arginfo;
	char canary[LINUX_AT_RANDOM_LEN];
	size_t execpath_len;
	struct proc *p;
	int argc, envc, error;

	p = imgp->proc;
	printf("stacktop:%lx\n",p->p_vmspace->vm_stacktop);
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
	vectp -= imgp->args->argc + 1 + imgp->args->envc + 1;

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
		aux_vec = (uintptr_t)vectp;
		error = imgp->sysent->sv_copyout_auxargs(imgp,
		    (uintptr_t)vectp);
		if (error != 0)
			return (error);
	}

	return (0);
}

static void
cleanup_power_extras(struct thread *td)
{
	uint32_t pcb_flags;

	if (td != curthread)
		return;

	pcb_flags = td->td_pcb->pcb_flags;
	/* Clean up registers not managed by MSR. */
	if (pcb_flags & PCB_CFSCR)
		mtspr(SPR_FSCR, 0);
	if (pcb_flags & PCB_CDSCR) 
		mtspr(SPR_DSCRP, 0);

	//if (pcb_flags & PCB_FPU)
		//cleanup_fpscr();
}


static void  
linux_exec_setregs_funcdesc(struct thread *td, struct image_params *imgp,
    uintptr_t stack)
{
	struct trapframe *tf;
	register_t entry_desc[3];

	tf = trapframe(td);
	linux_exec_setregs(td, imgp, stack);

	/*
	 * For 64-bit ELFv1, we need to disentangle the function
	 * descriptor
	 *
	 * 0. entry point
	 * 1. TOC value (r2)
	 * 2. Environment pointer (r11)
	 */

	(void)copyin((void *)imgp->entry_addr, entry_desc,
	    sizeof(entry_desc));
	tf->srr0 = entry_desc[0] + imgp->reloc_base;
	tf->fixreg[2] = entry_desc[1] + imgp->reloc_base;
	tf->fixreg[11] = entry_desc[2] + imgp->reloc_base;
}

/*
 * Reset registers to default values on exec.
 */
static void
linux_exec_setregs(struct thread *td, struct image_params *imgp,
    uintptr_t stack)
{
	uprintf(__func__);
	uprintf("\n");
	struct trapframe	*tf;
	register_t		argc;

	tf = trapframe(td);
	bzero(tf, sizeof *tf);
	#ifdef __powerpc64__
	//tf->fixreg[1] = -roundup(-stack + 48, 16);
	tf->fixreg[1] = stack;
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
	tf->fixreg[6] = aux_vec;				/* auxillary vector */
	tf->fixreg[7] = 0;				/* termination vector */
	tf->fixreg[8] = (register_t)imgp->ps_strings;	/* NetBSD extension */

	tf->srr0 = imgp->entry_addr;
	#ifdef __powerpc64__
	tf->fixreg[12] = imgp->entry_addr;
	#endif
	tf->srr1 = psl_userset | PSL_FE_DFLT;
	// TODO
	cleanup_power_extras(td);
	td->td_pcb->pcb_flags = 0;


}

void linux_dump_signal_frame(int *l_rt_sigframe){
    printf("----------------------------------------\n");
    //for(int i=0;i<LINUX__SIGNAL_FRAMESIZE;i++){
    for(int i=0;i<128;i++){
        printf("%02x",*((char*)l_rt_sigframe+i));
        if(i%2==1){
            printf(" ");
        }
        if(i%16==15){
            printf("\n");
        }
    }
    printf("----------------------------------------\n");
}


int
linux_rt_sigreturn(struct thread *td, struct linux_rt_sigreturn_args *args)
{
	struct l_sigframe *frame;
	ucontext_t uc;
	struct trapframe *tf;
	int error;

	printf("linux_rt_sigreturn called\n");
	tf = td->td_frame;
	frame = (struct l_sigframe *)tf->fixreg[1];
	printf("frame:%lx\n",(unsigned long)frame);

	if (copyin((void *)&frame->f_uc, &uc, sizeof(uc)))
		return (EFAULT);

	error = set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	/* Restore signal mask. */
	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

static void
linux_rt_sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct thread *td;
	struct proc *p;
	struct trapframe *tf;
	struct l_sigframe *fp, *frame;
	struct l_rt_sigframe *l_frame;
	l_stack_t uc_stack;
	ucontext_t f_uc;
	struct sigacts *psp;
	int onstack, sig, issiginfo;
	unsigned long newsp;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	tf = td->td_frame;
	onstack = sigonstack(tf->fixreg[1]);
	issiginfo = SIGISMEMBER(psp->ps_siginfo, sig);


	fp = (struct l_sigframe *)td->td_frame->fixreg[1];
		
	/* Might need to keep the stack align */
	fp--;

	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);
	get_mcontext(td, &f_uc.uc_mcontext, 0);
	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
	
	f_uc.uc_sigmask = *mask;
	/* What about the other ucontext_t member variables? No need to initialize? */

	uc_stack.ss_sp = PTROUT(td->td_sigstk.ss_sp);
	uc_stack.ss_size = td->td_sigstk.ss_size;
	uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? LINUX_SS_ONSTACK : 0) : LINUX_SS_DISABLE;

	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);

	/* Fill in the frame to copy out */
	frame = malloc(sizeof(*frame), M_LINUX, M_WAITOK | M_ZERO);
	memcpy(&frame->f_uc, &f_uc, sizeof(f_uc));
	l_frame = (struct l_rt_sigframe*)frame;

	l_frame->pinfo = &l_frame->info;
	l_frame->puc = &l_frame->uc;

	///* Create the l_ucontext */
	l_frame->uc.uc_flags = 0;
	memcpy(&l_frame->uc.uc_stack, &uc_stack, sizeof(uc_stack));
	l_frame->uc.uc_link = 0;
	///* __unsafe_setup_sigcontext() */
	unsigned long softe = 0x1;
	l_frame->uc.uc_mcontext.v_regs = 0;	
	///* if CONFIG_VSX or CONFIG_PPC_FPU_REGS is defined, unsafe_copy_fpr_to_usr() must be called */
	l_frame->uc.uc_mcontext.regs = (struct l_user_pt_regs*)&l_frame->uc.uc_mcontext.gp_regs;
	memcpy(&l_frame->uc.uc_mcontext.gp_regs, &tf, GP_REGS_SIZE);
	l_frame->uc.uc_mcontext.gp_regs[PT_SOFTE] = softe;
	sig = bsd_to_linux_signal(sig);
	l_frame->uc.uc_mcontext.signal = sig;
	l_frame->uc.uc_mcontext.handler = (unsigned long)catcher;

	bsd_to_linux_sigset(mask, &l_frame->uc.uc_sigmask);

	siginfo_to_lsiginfo(&ksi->ksi_info, &l_frame->info, sig);

	/* Might need to make sure signal handler doesn't get spurious FP exceptions? */
	//l_frame->tramp[0] = 0x4e800421;

	/* Copy the sigframe out to the user's stack. */
	if (copyout(frame, fp, sizeof(*fp)) != 0) {
		/* Process has trashed its stack. Kill it. */
		free(frame, M_LINUX);
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}
	free(frame, M_LINUX);

	/* Set up to return from userspace. */
	tf->srr0 = (register_t)linux_vdso_sigcode;
	printf("srr0:%lx\n",(unsigned long)linux_vdso_sigcode);
	//tf->srr0 = (register_t)&fp->sf.tramp[0];
	//printf("srr0:%lx\n",(unsigned long)&fp->sf.tramp[0]);

	/* Allocate a dummy caller frame for the signal handler. */
	printf("fp:%lx\n",(unsigned long)fp);
	newsp = (unsigned long)fp - LINUX__SIGNAL_FRAMESIZE;

	/* For ELFv1 */
	/* Handler is *really* a pointer to the function descriptor for
	* the signal routine.  The first entry in the function
	* descriptor is the entry address of signal and the second
	* entry is the TOC value we need to use.
	*/
	struct l_func_desc *ptr = (struct l_func_desc*)catcher;
	printf("ptr->addr:%lx\n",ptr->addr);
	tf->ctr = (register_t)ptr->addr;
	printf("ptr->toc:%lx\n",ptr->toc);
	//tf->fixreg[2] = (register_t)ptr->toc;

	tf->fixreg[1] = (register_t)newsp;
	tf->fixreg[3] = (register_t)sig;

	if(issiginfo){
		tf->fixreg[4] = (register_t)&fp->sf.info;
		tf->fixreg[5] = (register_t)&fp->sf.uc;
		tf->fixreg[6] = (register_t)&fp->sf;
	}else{
		tf->fixreg[4] = (register_t)&fp->sf.uc.uc_mcontext;
	}

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
	printf("sendsig end\n");
}

struct sysentvec elf_linux_sysvec = {
	.sv_size	= LINUX_SYS_MAXSYSCALL,
	.sv_table	= linux_sysent,
//	.sv_fixup	= linux_elf_fixup,
	.sv_fixup	= __elfN(freebsd_fixup),
	.sv_sendsig	= linux_rt_sendsig,
	//.sv_sigcode	= &_binary_linux_vdso_so_o_start,
	.sv_sigcode	= NULL,
	.sv_szsigcode	= &linux_szsigcode,
	.sv_name	= "Linux ELF64",
	.sv_coredump	= elf64_coredump,
	.sv_elf_core_osabi = ELFOSABI_NONE,
	.sv_elf_core_abi_vendor = LINUX_ABI_VENDOR,
	.sv_elf_core_prepare_notes = linux64_prepare_notes,
	.sv_imgact_try	= linux_exec_imgact_try,
	.sv_minsigstksz	= LINUX_MINSIGSTKSZ,
	.sv_minuser	= VM_MIN_ADDRESS,
	.sv_maxuser	= VM_MAXUSER_ADDRESS,
	.sv_usrstack	= LINUX_USRSTACK,
	.sv_psstrings	= LINUX_PS_STRINGS,
	.sv_psstringssz	= sizeof(struct ps_strings),
	.sv_stackprot	= VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, /* Enabling the execution of stack temporarily for signal trampoline. */
	.sv_copyout_auxargs = linux_copyout_auxargs,
	.sv_copyout_strings = linux_copyout_strings,
	//.sv_setregs	= linux_exec_setregs,
	.sv_setregs	= linux_exec_setregs_funcdesc,
	.sv_fixlimit	= NULL,
	.sv_maxssiz	= NULL,
	.sv_flags	= SV_ABI_LINUX | SV_LP64 | SV_SHP | SV_SIG_DISCIGN |
	    SV_SIG_WAITNDQ,
	.sv_set_syscall_retval = linux_set_syscall_retval,
	.sv_fetch_syscall_args = linux_fetch_syscall_args,
	.sv_syscallnames = NULL,
	.sv_shared_page_base = LINUX_SHAREDPAGE,
	.sv_shared_page_len = PAGE_SIZE,
	.sv_schedtail	= linux_schedtail,
	.sv_thread_detach = linux_thread_detach,
	.sv_trap	= NULL,
	.sv_hwcap	= NULL,
	.sv_hwcap2	= NULL,
	.sv_onexec	= linux_on_exec_vmspace,
	.sv_onexit	= linux_on_exit,
	.sv_ontdexit	= linux_thread_dtor,
	.sv_setid_allowed = &linux_setid_allowed_query,
};

static int
linux_on_exec_vmspace(struct proc *p, struct image_params *imgp)
{
	int error;

	printf("linux_vdso_obj:%lx\n",(unsigned long)linux_vdso_obj);
	error = linux_map_vdso(p, linux_vdso_obj, linux_vdso_base,
	    LINUX_VDSOPAGE_SIZE, imgp);
	if (error == 0)
		linux_on_exec(p, imgp);
	return (0);
}

/*
 * linux_vdso_install() and linux_exec_sysvec_init() must be called
 * after exec_sysvec_init() which is SI_SUB_EXEC (SI_ORDER_ANY).
 */
//static void
//linux_exec_sysvec_init(void *param)
//{
	//l_uintptr_t *ktimekeep_base;
	//struct sysentvec *sv;
	//ptrdiff_t tkoff;

	//sv = param;
	///* Fill timekeep_base */
	//exec_sysvec_init(sv);

	//tkoff = kern_timekeep_base - linux_vdso_base;
	//ktimekeep_base = (l_uintptr_t *)(linux_vdso_mapping + tkoff);
	//*ktimekeep_base = sv->sv_timekeep_base;
//}
//SYSINIT(elf_linux_exec_sysvec_init, SI_SUB_EXEC + 1, SI_ORDER_ANY,
    //linux_exec_sysvec_init, &elf_linux_sysvec);

static void
linux_vdso_install(const void *param)
{
	//char *vdso_start = &_binary_linux_vdso_so_o_start;
	//char *vdso_end = &_binary_linux_vdso_so_o_end;
	char *vdso_start = &_binary_linux_locore_o_start;
	char *vdso_end = &_binary_linux_locore_o_end;

	linux_szsigcode = vdso_end - vdso_start;
	MPASS(linux_szsigcode <= LINUX_VDSOPAGE_SIZE);

	linux_vdso_base = LINUX_VDSOPAGE;

	__elfN(linux_vdso_fixup)(vdso_start, linux_vdso_base);

	linux_vdso_obj = __elfN(linux_shared_page_init)
	    (&linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
	bcopy(vdso_start, linux_vdso_mapping, linux_szsigcode);
	printf("linux_vdso_mapping:%lx\n",(unsigned long)linux_vdso_mapping);

	linux_vdso_reloc(linux_vdso_mapping, linux_vdso_base);
}
SYSINIT(elf_linux_vdso_init, SI_SUB_EXEC + 1, SI_ORDER_FIRST,
    linux_vdso_install, NULL);

static void
linux_vdso_deinstall(const void *param)
{

	__elfN(linux_shared_page_fini)(linux_vdso_obj,
	    linux_vdso_mapping, LINUX_VDSOPAGE_SIZE);
}
SYSUNINIT(elf_linux_vdso_uninit, SI_SUB_EXEC, SI_ORDER_FIRST,
    linux_vdso_deinstall, NULL);

static void
linux_vdso_reloc(char *mapping, Elf_Addr offset)
{
	Elf_Size rtype, symidx;
	const Elf_Rela *rela;
	const Elf_Shdr *shdr;
	const Elf_Ehdr *ehdr;
	Elf_Addr *where;
	Elf_Addr addr, addend;
	int i, relacnt;

	MPASS(offset != 0);

	relacnt = 0;
	ehdr = (const Elf_Ehdr *)mapping;
	shdr = (const Elf_Shdr *)(mapping + ehdr->e_shoff);
	for (i = 0; i < ehdr->e_shnum; i++)
	{
		switch (shdr[i].sh_type) {
		case SHT_REL:
			printf("Linux Powerpc64 vDSO: unexpected Rel section\n");
			break;
		case SHT_RELA:
			rela = (const Elf_Rela *)(mapping + shdr[i].sh_offset);
			relacnt = shdr[i].sh_size / sizeof(*rela);
		}
	}

	for (i = 0; i < relacnt; i++, rela++) {
		where = (Elf_Addr *)(mapping + rela->r_offset);
		addend = rela->r_addend;
		rtype = ELF_R_TYPE(rela->r_info);
		symidx = ELF_R_SYM(rela->r_info);

		switch (rtype) {
		case R_PPC_NONE:	/* none */
			break;

		case R_PPC_RELATIVE:	/* B + A */
			addr = (Elf_Addr)(mapping + addend);
			if (*where != addr)
				*where = addr;
			break;
		default:
			printf("Linux Powerpc64 vDSO: unexpected relocation type %ld, "
			    "symbol index %ld\n", rtype, symidx);
		}
	}
}
static char GNU_ABI_VENDOR[] = "GNU";
static int GNU_ABI_LINUX = 0;

/* LINUXTODO: deduplicate */
static bool
linux_trans_osrel(const Elf_Note *note, int32_t *osrel)
{
	uprintf(__func__);
	uprintf("\n");
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
	uprintf(__func__);
	uprintf("\n");
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
				printf("Linux powerpc64 ELF exec handler removed\n");
		} else
			printf("Could not deinstall Linux powerpc64 ELF interpreter entry\n");
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
