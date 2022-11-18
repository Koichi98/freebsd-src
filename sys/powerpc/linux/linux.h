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
#define	LINUX_AT_COUNT		18

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
	l_time_t	tv_sec;
	l_long		tv_nsec;
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
	l_uint		st_mode;
	l_uint		st_nlink;

	l_uid_t		st_uid;
	l_gid_t		st_gid;

	l_dev_t		st_rdev;
	l_ulong		__st_pad1;
	l_off_t		st_size;
	l_int		st_blksize;
	l_int		__st_pad2;
	l_long		st_blocks;

	struct l_timespec	st_atim;
	struct l_timespec	st_mtim;
	struct l_timespec	st_ctim;
	l_uint		__unused1;
	l_uint		__unused2;
};


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


#endif /* _POWERPC_LINUX_H_ */
