/*-
 * Copyright (c) 1994-1996 Søren Schmidt
 * Copyright (c) 2013 Dmitry Chagin <dchagin@FreeBSD.org>
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

/*
 * $FreeBSD$
 */
#ifndef _POWERPC_LINUX_H_
#define	_POWERPC_LINUX_H_

#include <sys/abi_compat.h>

#include <compat/linux/linux.h>
#include <powerpc/linux/linux_syscall.h>

#define LINUX_LEGACY_SYSCALLS

#define	LINUX_DTRACE	linuxulator

/* Provide a separate set of types for the Linux types */
typedef int32_t		l_int;
typedef int64_t		l_long;
typedef int16_t		l_short;
typedef uint32_t	l_uint;
typedef uint64_t	l_ulong;
typedef uint16_t	l_ushort;

typedef l_ulong		l_uintptr_t;
typedef l_long		l_clock_t;
typedef l_int		l_daddr_t;
typedef l_ulong		l_dev_t;
typedef l_uint		l_gid_t;
typedef l_ushort	l_gid16_t;	/* XXX */
typedef l_uint		l_uid_t;
typedef l_ushort	l_uid16_t;	/* XXX */
typedef l_ulong		l_ino_t;
typedef l_int		l_key_t;
typedef l_long		l_loff_t;
typedef l_uint		l_mode_t;
typedef l_long		l_off_t;
typedef l_int		l_pid_t;
typedef l_ulong		l_size_t;
typedef l_long		l_suseconds_t;
typedef l_long		l_time_t;
typedef l_int		l_timer_t;	/* XXX */
typedef l_int		l_mqd_t;
typedef l_ulong		l_fd_mask;

#include <compat/linux/linux_siginfo.h>

typedef struct {
	l_int		val[2];
} l_fsid_t;

typedef struct {
	l_time_t	tv_sec;
	l_suseconds_t	tv_usec;
} l_timeval;

#define	l_fd_set	fd_set

///* Miscellaneous */
#define	LINUX_AT_COUNT		17

struct l___sysctl_args
{
	l_uintptr_t	name;
	l_int		nlen;
	l_uintptr_t	oldval;
	l_uintptr_t	oldlenp;
	l_uintptr_t	newval;
	l_uintptr_t	newlen;
	l_ulong		__spare[4];
};

/* Resource limits */
#define	LINUX_RLIMIT_CPU	0
#define	LINUX_RLIMIT_FSIZE	1
#define	LINUX_RLIMIT_DATA	2
#define	LINUX_RLIMIT_STACK	3
#define	LINUX_RLIMIT_CORE	4
#define	LINUX_RLIMIT_RSS	5
#define	LINUX_RLIMIT_NPROC	6
#define	LINUX_RLIMIT_NOFILE	7
#define	LINUX_RLIMIT_MEMLOCK	8
#define	LINUX_RLIMIT_AS		9	/* Address space limit */

#define	LINUX_RLIM_NLIMITS	10

struct l_rlimit {
	l_ulong		rlim_cur;
	l_ulong		rlim_max;
};

/* stat family of syscalls */
struct l_timespec {
	l_ulong		tv_sec;
	l_ulong		tv_nsec;
};

#define LINUX_O_DIRECTORY      040000	/* must be a directory */
#define LINUX_O_NOFOLLOW      0100000	/* don't follow links */
#define LINUX_O_LARGEFILE     0200000
#define LINUX_O_DIRECT	0400000	/* direct disk access hint */

/* Definitions for syscalls */
#define	LINUX_FIRSTARG	3				/* first arg in reg 3 */
#define	LINUX_NARGREG	8				/* 8 args in regs */

struct l_newstat {
	l_dev_t		st_dev;
	l_ino_t		st_ino;
	l_ulong 	st_nlink;
	l_uint		st_mode;

	l_uid_t		st_uid;
	l_gid_t		st_gid;

	l_dev_t		st_rdev;
	l_long		st_size;
	l_ulong		st_blksize;
	l_ulong		st_blocks;

	struct l_timespec	st_atim;
	struct l_timespec	st_mtim;
	struct l_timespec	st_ctim;
	l_ulong		__unused1;
	l_ulong		__unused2;
	l_ulong		__unused3;
};

struct l_statfs64 {
	l_int		f_type;
	l_int		f_bsize;
	uint64_t	f_blocks;
	uint64_t	f_bfree;
	uint64_t	f_bavail;
	uint64_t	f_files;
	uint64_t	f_ffree;
	l_fsid_t	f_fsid;
	l_int		f_namelen;
	l_int		f_frsize;
	l_int		f_flags;
	l_int		f_spare[4];
};

/* sigaction flags */
#define	LINUX_SA_NOCLDSTOP	0x00000001
#define	LINUX_SA_NOCLDWAIT	0x00000002
#define	LINUX_SA_SIGINFO	0x00000004
#define	LINUX_SA_RESTORER	0x04000000
#define	LINUX_SA_ONSTACK	0x08000000
#define	LINUX_SA_RESTART	0x10000000
#define	LINUX_SA_INTERRUPT	0x20000000	/* XXX */
#define	LINUX_SA_NOMASK		0x40000000	/* SA_NODEFER */
#define	LINUX_SA_ONESHOT	0x80000000	/* SA_RESETHAND */

/* sigaltstack */
#define	LINUX_MINSIGSTKSZ	8192
#define LINUX_SIGSTKSZ		32768

typedef void	(*l_handler_t)(l_int);

typedef struct {
	l_handler_t	lsa_handler;
	l_ulong		lsa_flags;
	l_uintptr_t	lsa_restorer;
	l_sigset_t 	lsa_mask;
} l_sigaction_t;				/* XXX */

typedef struct {
	l_uintptr_t	ss_sp;
	l_int		ss_flags;
	l_size_t	ss_size;
} l_stack_t;

union l_semun {
	l_int		val;
	l_uintptr_t	buf;
	l_uintptr_t	array;
	l_uintptr_t	__buf;
	l_uintptr_t	__pad;
};

struct l_ifmap {
	l_ulong		mem_start;
	l_ulong		mem_end;
	l_ushort	base_addr;
	u_char		irq;
	u_char		dma;
	u_char		port;
	/* 3 bytes spare*/
};

struct l_ifreq {
	union {
		char	ifrn_name[LINUX_IFNAMSIZ];
	} ifr_ifrn;

	union {
		struct l_sockaddr	ifru_addr;
		struct l_sockaddr	ifru_dstaddr;
		struct l_sockaddr	ifru_broadaddr;
		struct l_sockaddr	ifru_netmask;
		struct l_sockaddr	ifru_hwaddr;
		l_short		ifru_flags[1];
		l_int		ifru_ivalue;
		l_int		ifru_mtu;
		struct l_ifmap	ifru_map;
		char		ifru_slave[LINUX_IFNAMSIZ];
		l_uintptr_t	ifru_data;
	} ifr_ifru;
};

#define	ifr_name	ifr_ifrn.ifrn_name	/* Interface name */
#define	ifr_hwaddr	ifr_ifru.ifru_hwaddr	/* MAC address */
#define	ifr_ifindex	ifr_ifru.ifru_ivalue	/* Interface index */

#define	linux_copyout_rusage(r, u)	copyout(r, u, sizeof(*r))

/* robust futexes */
struct linux_robust_list {
	l_uintptr_t			next;
};

struct linux_robust_list_head {
	struct linux_robust_list	list;
	l_long				futex_offset;
	l_uintptr_t			pending_list;
};

struct reg;
struct syscall_info;

struct linux_pt_regset {
};


#ifdef _KERNEL
struct reg;
struct syscall_info;

void	bsd_to_linux_regset(const struct reg *b_reg,
	    struct linux_pt_regset *l_regset);
void	linux_to_bsd_regset(struct reg *b_reg,
	    const struct linux_pt_regset *l_regset);
void	linux_ptrace_get_syscall_info_machdep(const struct reg *reg,
	    struct syscall_info *si);
int	linux_ptrace_getregs_machdep(struct thread *td, pid_t pid,
	    struct linux_pt_regset *l_regset);
#endif /* _KERNEL */


/*
 * ioctl
 *
 * XXX comments in Linux' <asm-generic/ioctl.h> indicate these
 * could be arch-dependant...
 */
#define LINUX_IOCTL
#define LINUX_IOC_VOID		0x20000000
#define LINUX_IOC_IN		0x40000000
#define LINUX_IOC_OUT		0x80000000
#define LINUX_IOC_INOUT		(LINUX_IOC_IN|LINUX_IOC_OUT)


/*
 * termio
 */
#define LINUX_CFLAGS
#define	LINUX_TCGETS		0x7413
#define	LINUX_TCSETSW		0x7415
#define	LINUX_TIOCSWINSZ	0x7467
#define	LINUX_TIOCGWINSZ	0x7468
#define	LINUX_TIOCSPGRP		0x7476
#define	LINUX_TIOCGPGRP		0x7477

#define	LINUX_IOCTL_TERMIO_MAX	LINUX_TIOCGPGRP

/* c_cc characters */
#define LINUX_VINTR 	         0
#define LINUX_VQUIT 	         1
#define LINUX_VERASE 	         2
#define LINUX_VKILL	         3
#define LINUX_VEOF	         4
#define LINUX_VMIN	         5
#define LINUX_VEOL	         6
#define LINUX_VTIME	         7
#define LINUX_VEOL2	         8
#define LINUX_VSWTC	         9
#define LINUX_VWERASE 	10
#define LINUX_VREPRINT	11
#define LINUX_VSUSP 		12
#define LINUX_VSTART		13
#define LINUX_VSTOP		14
#define LINUX_VLNEXT		15
#define LINUX_VDISCARD	16

/* c_iflag bits */
#define LINUX_IXON	0x0200
#define LINUX_IXOFF	0x0400
#define LINUX_IUCLC	0x1000
#define LINUX_IMAXBEL	0x2000
#define LINUX_IUTF8	0x4000

/* c_oflag bits */
#define LINUX_ONLCR	0x00002
#define LINUX_OLCUC	0x00004
#define LINUX_NLDLY	0x00300
#define   LINUX_NL0	0x00000
#define   LINUX_NL1	0x00100
#define LINUX_TABDLY	0x00c00
#define   LINUX_TAB0	0x00000
#define   LINUX_TAB1	0x00400
#define   LINUX_TAB2	0x00800
#define   LINUX_TAB3	0x00c00
#define   LINUX_XTABS	0x00c00		/* required by POSIX to == TAB3 */
#define LINUX_CRDLY	0x03000
#define   LINUX_CR0	0x00000
#define   LINUX_CR1	0x01000
#define   LINUX_CR2	0x02000
#define   LINUX_CR3	0x03000
#define LINUX_FFDLY	0x04000
#define   LINUX_FF0	0x00000
#define   LINUX_FF1	0x04000
#define LINUX_BSDLY	0x08000
#define   LINUX_BS0	0x00000
#define   LINUX_BS1	0x08000
#define LINUX_VTDLY	0x10000
#define   LINUX_VT0	0x00000
#define   LINUX_VT1	0x10000

/* c_cflag bit meaning */
#define LINUX_CBAUD		0x000000ff
#define LINUX_CBAUDEX	0x00000000
#define LINUX_BOTHER	0x0000001f
#define LINUX_CSIZE		0x00000300
#define LINUX_CS5		0x00000000
#define LINUX_CS6		0x00000100
#define LINUX_CS7		0x00000200
#define LINUX_CS8		0x00000300
#define LINUX_CSTOPB	0x00000400
#define LINUX_CREAD		0x00000800
#define LINUX_PARENB	0x00001000
#define LINUX_PARODD	0x00002000
#define LINUX_HUPCL		0x00004000
#define LINUX_CLOCAL	0x00008000

/* c_lflag bits */
#define LINUX_ISIG	0x00000080
#define LINUX_ICANON	0x00000100
#define LINUX_XCASE	0x00004000
#define LINUX_ECHO	0x00000008
#define LINUX_ECHOE	0x00000002
#define LINUX_ECHOK	0x00000004
#define LINUX_ECHONL	0x00000010
#define LINUX_NOFLSH	0x80000000
#define LINUX_TOSTOP	0x00400000
#define LINUX_ECHOCTL	0x00000040
#define LINUX_ECHOPRT	0x00000020
#define LINUX_ECHOKE	0x00000001
#define LINUX_FLUSHO	0x00800000
#define LINUX_PENDIN	0x20000000
#define LINUX_IEXTEN	0x00000400

struct l_func_desc {
	unsigned long addr;
	unsigned long toc;
	unsigned long env;
};

#endif /* _POWERPC_LINUX_H_ */
