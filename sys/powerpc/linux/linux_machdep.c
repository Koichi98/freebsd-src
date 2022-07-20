/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Turing Robotic Industries Inc.
 * Copyright (c) 2000 Marcel Moolenaar
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/ktr.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
//#include <sys/reg.h>
#include <sys/sdt.h>

#include <powerpc/linux/linux.h>
#include <powerpc/linux/linux_proto.h>
#include <compat/linux/linux_dtrace.h>
#include <compat/linux/linux_fork.h>
#include <compat/linux/linux_misc.h>
#include <compat/linux/linux_mmap.h>
#include <compat/linux/linux_util.h>



int
linux_mmap2(struct thread *td, struct linux_mmap2_args *uap)
{

	return (linux_mmap_common(td, PTROUT(uap->addr), uap->len, uap->prot,
	    uap->flags, uap->fd, uap->pgoff));
}

int
linux_mprotect(struct thread *td, struct linux_mprotect_args *uap)
{

	return (linux_mprotect_common(td, PTROUT(uap->addr), uap->len,
	    uap->prot));
}

int
linux_madvise(struct thread *td, struct linux_madvise_args *uap)
{

	return (linux_madvise_common(td, PTROUT(uap->addr), uap->len, uap->behav));
}

int
linux_set_upcall(struct thread *td, register_t stack)
{
	//TODO
	return 0;
}

int
linux_set_cloned_tls(struct thread *td, void *desc)
{
	//TODO
	return 0;
}

void
bsd_to_linux_regset(const struct reg *b_reg, struct linux_pt_regset *l_regset)
{
	//TODO
}

void
linux_to_bsd_regset(struct reg *b_reg, const struct linux_pt_regset *l_regset)
{
	//TODO
}

void
linux_ptrace_get_syscall_info_machdep(const struct reg *reg,
    struct syscall_info *si)
{
	//TODO
}

int
linux_ptrace_getregs_machdep(struct thread *td, pid_t pid,
    struct linux_pt_regset *l_regset)
{
	//TODO
	return 0;
}

int
linux_pause(struct thread *td, struct linux_pause_args *args)
{
	return 0;
}

int
linux_ioperm(struct thread *td, struct linux_ioperm_args *args)
{
	return 0;
}

int
linux_iopl(struct thread *td, struct linux_iopl_args *args)
{
	return 0;
}

int
linux_modify_ldt(struct thread *td, struct linux_modify_ldt_args *uap)
{
	return 0;
}

/* XXX: this wont work with module - convert it */
int
linux_mq_open(struct thread *td, struct linux_mq_open_args *args)
{
	return 0;
}

int
linux_mq_unlink(struct thread *td, struct linux_mq_unlink_args *args)
{
	return 0;
}

int
linux_mq_timedsend(struct thread *td, struct linux_mq_timedsend_args *args)
{
	return 0;
}

int
linux_mq_timedreceive(struct thread *td, struct linux_mq_timedreceive_args *args)
{
	return 0;
}

int
linux_mq_notify(struct thread *td, struct linux_mq_notify_args *args)
{
	return 0;
}

int
linux_mq_getsetattr(struct thread *td, struct linux_mq_getsetattr_args *args)
{
	return 0;
}

int	
linux_quotactl(struct thread *td, struct linux_quotactl_args * args)
{
	return 0;
}
