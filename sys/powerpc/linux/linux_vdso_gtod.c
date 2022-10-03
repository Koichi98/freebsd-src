/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2012 Konstantin Belousov <kib@FreeBSD.org>
 * Copyright (c) 2021 Dmitry Chagin <dchagin@FreeBSD.org>
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

#include <sys/elf.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stddef.h>
#define	_KERNEL
#include <sys/vdso.h>
#undef	_KERNEL
#include <stdbool.h>

#include <machine/cpufunc.h>

#include <powerpc/linux/linux.h>
#include <powerpc/linux/linux_syscall.h>
#include <compat/linux/linux_errno.h>
#include <compat/linux/linux_timer.h>

/* The kernel fixup this at vDSO install */
uintptr_t *kern_timekeep_base = NULL;
uint32_t kern_tsc_selector = 0;

static int
__vdso_clock_gettime_fallback(clockid_t clock_id, struct l_timespec *lts)
{
	return (0);
}

static int
__vdso_gettimeofday_fallback(l_timeval *ltv, struct timezone *ltz)
{
	return (0);
}

static int
__vdso_clock_getres_fallback(clockid_t clock_id, struct l_timespec *lts)
{
	return (0);
}

/*
 * copied from lib/libc/powerpc64/sys/__vdso_gettc.c
 */

int
__vdso_gettc(const struct vdso_timehands *th, u_int *tc)
{
	u_quad_t tb;

	if (__predict_false(th->th_algo != VDSO_TH_ALGO_PPC_TB))
		return (ENOSYS);

	__asm __volatile ("mftb %0" : "=r"(tb));
	*tc = tb;
	return (0);
}


#include <compat/linux/linux_vdso_gtod.inc>
