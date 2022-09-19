/*
 * System call argument to DTrace register array converstion.
 *
 * DO NOT EDIT-- this file is automatically @generated.
 * $FreeBSD$
 * This file is part of the DTrace syscall provider.
 */

static void
systrace_args(int sysnum, void *params, uint64_t *uarg, int *n_args)
{
	int64_t *iarg = (int64_t *)uarg;
	int a = 0;
	switch (sysnum) {
#define	nosys	linux_nosys
	/* linux_exit */
	case 1: {
		struct linux_exit_args *p = params;
		uarg[a++] = p->rval; /* u_int */
		*n_args = 1;
		break;
	}
	/* linux_fork */
	case 2: {
		*n_args = 0;
		break;
	}
	/* read */
	case 3: {
		struct read_args *p = params;
		iarg[a++] = p->fd; /* int */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->nbyte; /* l_size_t */
		*n_args = 3;
		break;
	}
	/* write */
	case 4: {
		struct write_args *p = params;
		iarg[a++] = p->fd; /* int */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->nbyte; /* l_size_t */
		*n_args = 3;
		break;
	}
	/* linux_open */
	case 5: {
		struct linux_open_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->flags; /* l_int */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 3;
		break;
	}
	/* close */
	case 6: {
		struct close_args *p = params;
		iarg[a++] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* linux_creat */
	case 8: {
		struct linux_creat_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 2;
		break;
	}
	/* linux_link */
	case 9: {
		struct linux_link_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->to; /* char * */
		*n_args = 2;
		break;
	}
	/* linux_unlink */
	case 10: {
		struct linux_unlink_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_execve */
	case 11: {
		struct linux_execve_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->argp; /* char ** */
		uarg[a++] = (intptr_t)p->envp; /* char ** */
		*n_args = 3;
		break;
	}
	/* linux_chdir */
	case 12: {
		struct linux_chdir_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_time */
	case 13: {
		struct linux_time_args *p = params;
		uarg[a++] = (intptr_t)p->tm; /* l_time_t * */
		*n_args = 1;
		break;
	}
	/* linux_mknod */
	case 14: {
		struct linux_mknod_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->mode; /* l_mode_t */
		iarg[a++] = p->dev; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_chmod */
	case 15: {
		struct linux_chmod_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 2;
		break;
	}
	/* linux_lchown */
	case 16: {
		struct linux_lchown_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->uid; /* l_uid_t */
		iarg[a++] = p->gid; /* l_gid_t */
		*n_args = 3;
		break;
	}
	/* linux_lseek */
	case 19: {
		struct linux_lseek_args *p = params;
		iarg[a++] = p->fdes; /* l_uint */
		iarg[a++] = p->off; /* l_off_t */
		iarg[a++] = p->whence; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_getpid */
	case 20: {
		*n_args = 0;
		break;
	}
	/* linux_mount */
	case 21: {
		struct linux_mount_args *p = params;
		uarg[a++] = (intptr_t)p->specialfile; /* char * */
		uarg[a++] = (intptr_t)p->dir; /* char * */
		uarg[a++] = (intptr_t)p->filesystemtype; /* char * */
		iarg[a++] = p->rwflag; /* l_ulong */
		uarg[a++] = (intptr_t)p->data; /* void * */
		*n_args = 5;
		break;
	}
	/* linux_umount */
	case 22: {
		struct linux_umount_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 2;
		break;
	}
	/* setuid */
	case 23: {
		struct setuid_args *p = params;
		uarg[a++] = p->uid; /* uid_t */
		*n_args = 1;
		break;
	}
	/* linux_getuid */
	case 24: {
		*n_args = 0;
		break;
	}
	/* linux_ptrace */
	case 26: {
		struct linux_ptrace_args *p = params;
		iarg[a++] = p->req; /* l_long */
		iarg[a++] = p->pid; /* l_long */
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->data; /* l_ulong */
		*n_args = 4;
		break;
	}
	/* linux_alarm */
	case 27: {
		struct linux_alarm_args *p = params;
		iarg[a++] = p->secs; /* l_uint */
		*n_args = 1;
		break;
	}
	/* linux_pause */
	case 29: {
		*n_args = 0;
		break;
	}
	/* linux_utime */
	case 30: {
		struct linux_utime_args *p = params;
		uarg[a++] = (intptr_t)p->fname; /* char * */
		uarg[a++] = (intptr_t)p->times; /* struct l_utimbuf * */
		*n_args = 2;
		break;
	}
	/* linux_access */
	case 33: {
		struct linux_access_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->amode; /* l_int */
		*n_args = 2;
		break;
	}
	/* sync */
	case 36: {
		*n_args = 0;
		break;
	}
	/* linux_kill */
	case 37: {
		struct linux_kill_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->signum; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_rename */
	case 38: {
		struct linux_rename_args *p = params;
		uarg[a++] = (intptr_t)p->from; /* char * */
		uarg[a++] = (intptr_t)p->to; /* char * */
		*n_args = 2;
		break;
	}
	/* linux_mkdir */
	case 39: {
		struct linux_mkdir_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 2;
		break;
	}
	/* linux_rmdir */
	case 40: {
		struct linux_rmdir_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		*n_args = 1;
		break;
	}
	/* dup */
	case 41: {
		struct dup_args *p = params;
		uarg[a++] = p->fd; /* u_int */
		*n_args = 1;
		break;
	}
	/* linux_pipe */
	case 42: {
		struct linux_pipe_args *p = params;
		uarg[a++] = (intptr_t)p->pipefds; /* l_int * */
		*n_args = 1;
		break;
	}
	/* linux_times */
	case 43: {
		struct linux_times_args *p = params;
		uarg[a++] = (intptr_t)p->buf; /* struct l_times_argv * */
		*n_args = 1;
		break;
	}
	/* linux_brk */
	case 45: {
		struct linux_brk_args *p = params;
		iarg[a++] = p->dsend; /* l_ulong */
		*n_args = 1;
		break;
	}
	/* setgid */
	case 46: {
		struct setgid_args *p = params;
		iarg[a++] = p->gid; /* gid_t */
		*n_args = 1;
		break;
	}
	/* linux_getgid */
	case 47: {
		*n_args = 0;
		break;
	}
	/* geteuid */
	case 49: {
		*n_args = 0;
		break;
	}
	/* getegid */
	case 50: {
		*n_args = 0;
		break;
	}
	/* acct */
	case 51: {
		struct acct_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_ioctl */
	case 54: {
		struct linux_ioctl_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		iarg[a++] = p->cmd; /* l_uint */
		iarg[a++] = p->arg; /* l_ulong */
		*n_args = 3;
		break;
	}
	/* linux_fcntl */
	case 55: {
		struct linux_fcntl_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		iarg[a++] = p->cmd; /* l_uint */
		iarg[a++] = p->arg; /* l_ulong */
		*n_args = 3;
		break;
	}
	/* setpgid */
	case 57: {
		struct setpgid_args *p = params;
		iarg[a++] = p->pid; /* int */
		iarg[a++] = p->pgid; /* int */
		*n_args = 2;
		break;
	}
	/* umask */
	case 60: {
		struct umask_args *p = params;
		iarg[a++] = p->newmask; /* int */
		*n_args = 1;
		break;
	}
	/* chroot */
	case 61: {
		struct chroot_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_ustat */
	case 62: {
		struct linux_ustat_args *p = params;
		iarg[a++] = p->dev; /* l_uint */
		uarg[a++] = (intptr_t)p->ubuf; /* struct l_ustat * */
		*n_args = 2;
		break;
	}
	/* dup2 */
	case 63: {
		struct dup2_args *p = params;
		uarg[a++] = p->from; /* u_int */
		uarg[a++] = p->to; /* u_int */
		*n_args = 2;
		break;
	}
	/* linux_getppid */
	case 64: {
		*n_args = 0;
		break;
	}
	/* getpgrp */
	case 65: {
		*n_args = 0;
		break;
	}
	/* setsid */
	case 66: {
		*n_args = 0;
		break;
	}
	/* setreuid */
	case 70: {
		struct setreuid_args *p = params;
		uarg[a++] = p->ruid; /* uid_t */
		uarg[a++] = p->euid; /* uid_t */
		*n_args = 2;
		break;
	}
	/* setregid */
	case 71: {
		struct setregid_args *p = params;
		iarg[a++] = p->rgid; /* gid_t */
		iarg[a++] = p->egid; /* gid_t */
		*n_args = 2;
		break;
	}
	/* linux_sethostname */
	case 74: {
		struct linux_sethostname_args *p = params;
		uarg[a++] = (intptr_t)p->hostname; /* char * */
		iarg[a++] = p->len; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_setrlimit */
	case 75: {
		struct linux_setrlimit_args *p = params;
		iarg[a++] = p->resource; /* l_uint */
		uarg[a++] = (intptr_t)p->rlim; /* struct l_rlimit * */
		*n_args = 2;
		break;
	}
	/* linux_getrlimit */
	case 76: {
		struct linux_getrlimit_args *p = params;
		iarg[a++] = p->resource; /* l_uint */
		uarg[a++] = (intptr_t)p->rlim; /* struct l_rlimit * */
		*n_args = 2;
		break;
	}
	/* getrusage */
	case 77: {
		struct getrusage_args *p = params;
		iarg[a++] = p->who; /* int */
		uarg[a++] = (intptr_t)p->rusage; /* struct rusage * */
		*n_args = 2;
		break;
	}
	/* gettimeofday */
	case 78: {
		struct gettimeofday_args *p = params;
		uarg[a++] = (intptr_t)p->tp; /* struct l_timeval * */
		uarg[a++] = (intptr_t)p->tzp; /* struct timezone * */
		*n_args = 2;
		break;
	}
	/* settimeofday */
	case 79: {
		struct settimeofday_args *p = params;
		uarg[a++] = (intptr_t)p->tv; /* struct l_timeval * */
		uarg[a++] = (intptr_t)p->tzp; /* struct timezone * */
		*n_args = 2;
		break;
	}
	/* linux_getgroups */
	case 80: {
		struct linux_getgroups_args *p = params;
		iarg[a++] = p->gidsetsize; /* l_int */
		uarg[a++] = (intptr_t)p->grouplist; /* l_gid_t * */
		*n_args = 2;
		break;
	}
	/* linux_setgroups */
	case 81: {
		struct linux_setgroups_args *p = params;
		iarg[a++] = p->gidsetsize; /* l_int */
		uarg[a++] = (intptr_t)p->grouplist; /* l_gid_t * */
		*n_args = 2;
		break;
	}
	/* linux_select */
	case 82: {
		struct linux_select_args *p = params;
		iarg[a++] = p->nfds; /* l_int */
		uarg[a++] = (intptr_t)p->readfds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->writefds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->exceptfds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timeval * */
		*n_args = 5;
		break;
	}
	/* linux_symlink */
	case 83: {
		struct linux_symlink_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->to; /* char * */
		*n_args = 2;
		break;
	}
	/* linux_readlink */
	case 85: {
		struct linux_readlink_args *p = params;
		uarg[a++] = (intptr_t)p->name; /* char * */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->count; /* l_int */
		*n_args = 3;
		break;
	}
	/* swapon */
	case 87: {
		struct swapon_args *p = params;
		uarg[a++] = (intptr_t)p->name; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_reboot */
	case 88: {
		struct linux_reboot_args *p = params;
		iarg[a++] = p->magic1; /* l_int */
		iarg[a++] = p->magic2; /* l_int */
		iarg[a++] = p->cmd; /* l_uint */
		uarg[a++] = (intptr_t)p->arg; /* void * */
		*n_args = 4;
		break;
	}
	/* linux_mmap */
	case 90: {
		struct linux_mmap_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->len; /* l_ulong */
		iarg[a++] = p->prot; /* l_ulong */
		iarg[a++] = p->flags; /* l_ulong */
		iarg[a++] = p->fd; /* l_ulong */
		iarg[a++] = p->pgoff; /* l_ulong */
		*n_args = 6;
		break;
	}
	/* munmap */
	case 91: {
		struct munmap_args *p = params;
		uarg[a++] = (intptr_t)p->addr; /* void * */
		iarg[a++] = p->len; /* l_size_t */
		*n_args = 2;
		break;
	}
	/* linux_truncate */
	case 92: {
		struct linux_truncate_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->length; /* l_long */
		*n_args = 2;
		break;
	}
	/* linux_ftruncate */
	case 93: {
		struct linux_ftruncate_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->length; /* l_ulong */
		*n_args = 2;
		break;
	}
	/* fchmod */
	case 94: {
		struct fchmod_args *p = params;
		iarg[a++] = p->fd; /* int */
		iarg[a++] = p->mode; /* int */
		*n_args = 2;
		break;
	}
	/* fchown */
	case 95: {
		struct fchown_args *p = params;
		iarg[a++] = p->fd; /* int */
		iarg[a++] = p->uid; /* int */
		iarg[a++] = p->gid; /* int */
		*n_args = 3;
		break;
	}
	/* linux_getpriority */
	case 96: {
		struct linux_getpriority_args *p = params;
		iarg[a++] = p->which; /* l_int */
		iarg[a++] = p->who; /* l_int */
		*n_args = 2;
		break;
	}
	/* setpriority */
	case 97: {
		struct setpriority_args *p = params;
		iarg[a++] = p->which; /* int */
		iarg[a++] = p->who; /* int */
		iarg[a++] = p->prio; /* int */
		*n_args = 3;
		break;
	}
	/* linux_statfs */
	case 99: {
		struct linux_statfs_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->buf; /* struct l_statfs_buf * */
		*n_args = 2;
		break;
	}
	/* linux_fstatfs */
	case 100: {
		struct linux_fstatfs_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->buf; /* struct l_statfs_buf * */
		*n_args = 2;
		break;
	}
	/* linux_ioperm */
	case 101: {
		*n_args = 0;
		break;
	}
	/* linux_syslog */
	case 103: {
		struct linux_syslog_args *p = params;
		iarg[a++] = p->type; /* l_int */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->len; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_setitimer */
	case 104: {
		struct linux_setitimer_args *p = params;
		iarg[a++] = p->which; /* l_int */
		uarg[a++] = (intptr_t)p->itv; /* struct l_itimerval * */
		uarg[a++] = (intptr_t)p->oitv; /* struct l_itimerval * */
		*n_args = 3;
		break;
	}
	/* linux_getitimer */
	case 105: {
		struct linux_getitimer_args *p = params;
		iarg[a++] = p->which; /* l_int */
		uarg[a++] = (intptr_t)p->itv; /* struct l_itimerval * */
		*n_args = 2;
		break;
	}
	/* linux_newstat */
	case 106: {
		struct linux_newstat_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->buf; /* struct l_newstat * */
		*n_args = 2;
		break;
	}
	/* linux_newlstat */
	case 107: {
		struct linux_newlstat_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		uarg[a++] = (intptr_t)p->buf; /* struct l_newstat * */
		*n_args = 2;
		break;
	}
	/* linux_newfstat */
	case 108: {
		struct linux_newfstat_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->buf; /* struct l_newstat * */
		*n_args = 2;
		break;
	}
	/* linux_iopl */
	case 110: {
		struct linux_iopl_args *p = params;
		iarg[a++] = p->level; /* l_uint */
		*n_args = 1;
		break;
	}
	/* linux_vhangup */
	case 111: {
		*n_args = 0;
		break;
	}
	/* linux_wait4 */
	case 114: {
		struct linux_wait4_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->status; /* l_int * */
		iarg[a++] = p->options; /* l_int */
		uarg[a++] = (intptr_t)p->rusage; /* struct rusage * */
		*n_args = 4;
		break;
	}
	/* linux_swapoff */
	case 115: {
		*n_args = 0;
		break;
	}
	/* linux_sysinfo */
	case 116: {
		struct linux_sysinfo_args *p = params;
		uarg[a++] = (intptr_t)p->info; /* struct l_sysinfo * */
		*n_args = 1;
		break;
	}
	/* fsync */
	case 118: {
		struct fsync_args *p = params;
		iarg[a++] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* linux_clone */
	case 120: {
		struct linux_clone_args *p = params;
		iarg[a++] = p->flags; /* l_ulong */
		iarg[a++] = p->stack; /* l_ulong */
		uarg[a++] = (intptr_t)p->parent_tidptr; /* l_int * */
		uarg[a++] = (intptr_t)p->child_tidptr; /* l_int * */
		iarg[a++] = p->tls; /* l_ulong */
		*n_args = 5;
		break;
	}
	/* linux_setdomainname */
	case 121: {
		struct linux_setdomainname_args *p = params;
		uarg[a++] = (intptr_t)p->name; /* char * */
		iarg[a++] = p->len; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_newuname */
	case 122: {
		struct linux_newuname_args *p = params;
		uarg[a++] = (intptr_t)p->buf; /* struct l_new_utsname * */
		*n_args = 1;
		break;
	}
	/* linux_modify_ldt */
	case 123: {
		*n_args = 0;
		break;
	}
	/* linux_adjtimex */
	case 124: {
		*n_args = 0;
		break;
	}
	/* linux_mprotect */
	case 125: {
		struct linux_mprotect_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->prot; /* l_ulong */
		*n_args = 3;
		break;
	}
	/* linux_init_module */
	case 128: {
		*n_args = 0;
		break;
	}
	/* linux_delete_module */
	case 129: {
		*n_args = 0;
		break;
	}
	/* linux_quotactl */
	case 131: {
		*n_args = 0;
		break;
	}
	/* getpgid */
	case 132: {
		struct getpgid_args *p = params;
		iarg[a++] = p->pid; /* int */
		*n_args = 1;
		break;
	}
	/* fchdir */
	case 133: {
		struct fchdir_args *p = params;
		iarg[a++] = p->fd; /* int */
		*n_args = 1;
		break;
	}
	/* linux_personality */
	case 136: {
		struct linux_personality_args *p = params;
		iarg[a++] = p->per; /* l_uint */
		*n_args = 1;
		break;
	}
	/* linux_setfsuid */
	case 138: {
		struct linux_setfsuid_args *p = params;
		iarg[a++] = p->uid; /* l_uid_t */
		*n_args = 1;
		break;
	}
	/* linux_setfsgid */
	case 139: {
		struct linux_setfsgid_args *p = params;
		iarg[a++] = p->gid; /* l_gid_t */
		*n_args = 1;
		break;
	}
	/* linux_getdents */
	case 141: {
		struct linux_getdents_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->dent; /* void * */
		iarg[a++] = p->count; /* l_uint */
		*n_args = 3;
		break;
	}
	/* flock */
	case 143: {
		struct flock_args *p = params;
		iarg[a++] = p->fd; /* int */
		iarg[a++] = p->how; /* int */
		*n_args = 2;
		break;
	}
	/* linux_msync */
	case 144: {
		struct linux_msync_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->fl; /* l_int */
		*n_args = 3;
		break;
	}
	/* readv */
	case 145: {
		struct readv_args *p = params;
		iarg[a++] = p->fd; /* int */
		uarg[a++] = (intptr_t)p->iovp; /* struct iovec * */
		uarg[a++] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* writev */
	case 146: {
		struct writev_args *p = params;
		iarg[a++] = p->fd; /* int */
		uarg[a++] = (intptr_t)p->iovp; /* struct iovec * */
		uarg[a++] = p->iovcnt; /* u_int */
		*n_args = 3;
		break;
	}
	/* linux_getsid */
	case 147: {
		struct linux_getsid_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		*n_args = 1;
		break;
	}
	/* linux_fdatasync */
	case 148: {
		struct linux_fdatasync_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		*n_args = 1;
		break;
	}
	/* linux_sysctl */
	case 149: {
		struct linux_sysctl_args *p = params;
		uarg[a++] = (intptr_t)p->args; /* struct l___sysctl_args * */
		*n_args = 1;
		break;
	}
	/* mlock */
	case 150: {
		struct mlock_args *p = params;
		uarg[a++] = (intptr_t)p->addr; /* const void * */
		uarg[a++] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* munlock */
	case 151: {
		struct munlock_args *p = params;
		uarg[a++] = (intptr_t)p->addr; /* const void * */
		uarg[a++] = p->len; /* size_t */
		*n_args = 2;
		break;
	}
	/* mlockall */
	case 152: {
		struct mlockall_args *p = params;
		iarg[a++] = p->how; /* int */
		*n_args = 1;
		break;
	}
	/* munlockall */
	case 153: {
		*n_args = 0;
		break;
	}
	/* linux_sched_setparam */
	case 154: {
		struct linux_sched_setparam_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->param; /* struct sched_param * */
		*n_args = 2;
		break;
	}
	/* linux_sched_getparam */
	case 155: {
		struct linux_sched_getparam_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->param; /* struct sched_param * */
		*n_args = 2;
		break;
	}
	/* linux_sched_setscheduler */
	case 156: {
		struct linux_sched_setscheduler_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->policy; /* l_int */
		uarg[a++] = (intptr_t)p->param; /* struct sched_param * */
		*n_args = 3;
		break;
	}
	/* linux_sched_getscheduler */
	case 157: {
		struct linux_sched_getscheduler_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		*n_args = 1;
		break;
	}
	/* sched_yield */
	case 158: {
		*n_args = 0;
		break;
	}
	/* linux_sched_get_priority_max */
	case 159: {
		struct linux_sched_get_priority_max_args *p = params;
		iarg[a++] = p->policy; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_sched_get_priority_min */
	case 160: {
		struct linux_sched_get_priority_min_args *p = params;
		iarg[a++] = p->policy; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_sched_rr_get_interval */
	case 161: {
		struct linux_sched_rr_get_interval_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->interval; /* struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_nanosleep */
	case 162: {
		struct linux_nanosleep_args *p = params;
		uarg[a++] = (intptr_t)p->rqtp; /* const struct l_timespec * */
		uarg[a++] = (intptr_t)p->rmtp; /* struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_mremap */
	case 163: {
		struct linux_mremap_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->old_len; /* l_ulong */
		iarg[a++] = p->new_len; /* l_ulong */
		iarg[a++] = p->flags; /* l_ulong */
		iarg[a++] = p->new_addr; /* l_ulong */
		*n_args = 5;
		break;
	}
	/* setresuid */
	case 164: {
		struct setresuid_args *p = params;
		uarg[a++] = p->ruid; /* uid_t */
		uarg[a++] = p->euid; /* uid_t */
		uarg[a++] = p->suid; /* uid_t */
		*n_args = 3;
		break;
	}
	/* getresuid */
	case 165: {
		struct getresuid_args *p = params;
		uarg[a++] = (intptr_t)p->ruid; /* uid_t * */
		uarg[a++] = (intptr_t)p->euid; /* uid_t * */
		uarg[a++] = (intptr_t)p->suid; /* uid_t * */
		*n_args = 3;
		break;
	}
	/* linux_poll */
	case 167: {
		struct linux_poll_args *p = params;
		uarg[a++] = (intptr_t)p->fds; /* struct pollfd * */
		uarg[a++] = p->nfds; /* u_int */
		iarg[a++] = p->timeout; /* int */
		*n_args = 3;
		break;
	}
	/* setresgid */
	case 169: {
		struct setresgid_args *p = params;
		iarg[a++] = p->rgid; /* gid_t */
		iarg[a++] = p->egid; /* gid_t */
		iarg[a++] = p->sgid; /* gid_t */
		*n_args = 3;
		break;
	}
	/* getresgid */
	case 170: {
		struct getresgid_args *p = params;
		uarg[a++] = (intptr_t)p->rgid; /* gid_t * */
		uarg[a++] = (intptr_t)p->egid; /* gid_t * */
		uarg[a++] = (intptr_t)p->sgid; /* gid_t * */
		*n_args = 3;
		break;
	}
	/* linux_prctl */
	case 171: {
		struct linux_prctl_args *p = params;
		iarg[a++] = p->option; /* l_int */
		uarg[a++] = (intptr_t)p->arg2; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->arg3; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->arg4; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->arg5; /* l_uintptr_t */
		*n_args = 5;
		break;
	}
	/* linux_rt_sigreturn */
	case 172: {
		*n_args = 0;
		break;
	}
	/* linux_rt_sigaction */
	case 173: {
		struct linux_rt_sigaction_args *p = params;
		iarg[a++] = p->sig; /* l_int */
		uarg[a++] = (intptr_t)p->act; /* l_sigaction_t * */
		uarg[a++] = (intptr_t)p->oact; /* l_sigaction_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_rt_sigprocmask */
	case 174: {
		struct linux_rt_sigprocmask_args *p = params;
		iarg[a++] = p->how; /* l_int */
		uarg[a++] = (intptr_t)p->mask; /* l_sigset_t * */
		uarg[a++] = (intptr_t)p->omask; /* l_sigset_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_rt_sigpending */
	case 175: {
		struct linux_rt_sigpending_args *p = params;
		uarg[a++] = (intptr_t)p->set; /* l_sigset_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 2;
		break;
	}
	/* linux_rt_sigtimedwait */
	case 176: {
		struct linux_rt_sigtimedwait_args *p = params;
		uarg[a++] = (intptr_t)p->mask; /* l_sigset_t * */
		uarg[a++] = (intptr_t)p->ptr; /* l_siginfo_t * */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timespec * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_rt_sigqueueinfo */
	case 177: {
		struct linux_rt_sigqueueinfo_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->sig; /* l_int */
		uarg[a++] = (intptr_t)p->info; /* l_siginfo_t * */
		*n_args = 3;
		break;
	}
	/* linux_rt_sigsuspend */
	case 178: {
		struct linux_rt_sigsuspend_args *p = params;
		uarg[a++] = (intptr_t)p->newset; /* l_sigset_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 2;
		break;
	}
	/* linux_pread */
	case 179: {
		struct linux_pread_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->nbyte; /* l_size_t */
		iarg[a++] = p->offset; /* l_loff_t */
		*n_args = 4;
		break;
	}
	/* linux_pwrite */
	case 180: {
		struct linux_pwrite_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->nbyte; /* l_size_t */
		iarg[a++] = p->offset; /* l_loff_t */
		*n_args = 4;
		break;
	}
	/* linux_chown */
	case 181: {
		struct linux_chown_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* char * */
		iarg[a++] = p->uid; /* l_uid_t */
		iarg[a++] = p->gid; /* l_gid_t */
		*n_args = 3;
		break;
	}
	/* linux_getcwd */
	case 182: {
		struct linux_getcwd_args *p = params;
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->bufsize; /* l_ulong */
		*n_args = 2;
		break;
	}
	/* linux_capget */
	case 183: {
		struct linux_capget_args *p = params;
		uarg[a++] = (intptr_t)p->hdrp; /* struct l_user_cap_header * */
		uarg[a++] = (intptr_t)p->datap; /* struct l_user_cap_data * */
		*n_args = 2;
		break;
	}
	/* linux_capset */
	case 184: {
		struct linux_capset_args *p = params;
		uarg[a++] = (intptr_t)p->hdrp; /* struct l_user_cap_header * */
		uarg[a++] = (intptr_t)p->datap; /* struct l_user_cap_data * */
		*n_args = 2;
		break;
	}
	/* linux_sigaltstack */
	case 185: {
		struct linux_sigaltstack_args *p = params;
		uarg[a++] = (intptr_t)p->uss; /* l_stack_t * */
		uarg[a++] = (intptr_t)p->uoss; /* l_stack_t * */
		*n_args = 2;
		break;
	}
	/* linux_sendfile */
	case 186: {
		struct linux_sendfile_args *p = params;
		iarg[a++] = p->out; /* l_int */
		iarg[a++] = p->in; /* l_int */
		uarg[a++] = (intptr_t)p->offset; /* l_off_t * */
		iarg[a++] = p->count; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_vfork */
	case 189: {
		*n_args = 0;
		break;
	}
	/* linux_mmap2 */
	case 192: {
		struct linux_mmap2_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->len; /* l_ulong */
		iarg[a++] = p->prot; /* l_ulong */
		iarg[a++] = p->flags; /* l_ulong */
		iarg[a++] = p->fd; /* l_ulong */
		iarg[a++] = p->pgoff; /* l_ulong */
		*n_args = 6;
		break;
	}
	/* linux_getdents64 */
	case 202: {
		struct linux_getdents64_args *p = params;
		iarg[a++] = p->fd; /* l_uint */
		uarg[a++] = (intptr_t)p->dirent; /* void * */
		iarg[a++] = p->count; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_pivot_root */
	case 203: {
		*n_args = 0;
		break;
	}
	/* linux_madvise */
	case 205: {
		struct linux_madvise_args *p = params;
		iarg[a++] = p->addr; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->behav; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_mincore */
	case 206: {
		struct linux_mincore_args *p = params;
		iarg[a++] = p->start; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		uarg[a++] = (intptr_t)p->vec; /* u_char * */
		*n_args = 3;
		break;
	}
	/* linux_gettid */
	case 207: {
		*n_args = 0;
		break;
	}
	/* linux_tkill */
	case 208: {
		struct linux_tkill_args *p = params;
		iarg[a++] = p->tid; /* l_pid_t */
		iarg[a++] = p->sig; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_setxattr */
	case 209: {
		struct linux_setxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_lsetxattr */
	case 210: {
		struct linux_lsetxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_fsetxattr */
	case 211: {
		struct linux_fsetxattr_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_getxattr */
	case 212: {
		struct linux_getxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_lgetxattr */
	case 213: {
		struct linux_lgetxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_fgetxattr */
	case 214: {
		struct linux_fgetxattr_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->value; /* char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 4;
		break;
	}
	/* linux_listxattr */
	case 215: {
		struct linux_listxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->list; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 3;
		break;
	}
	/* linux_llistxattr */
	case 216: {
		struct linux_llistxattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->list; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 3;
		break;
	}
	/* linux_flistxattr */
	case 217: {
		struct linux_flistxattr_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->list; /* const char * */
		iarg[a++] = p->size; /* l_size_t */
		*n_args = 3;
		break;
	}
	/* linux_removexattr */
	case 218: {
		struct linux_removexattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		*n_args = 2;
		break;
	}
	/* linux_lremovexattr */
	case 219: {
		struct linux_lremovexattr_args *p = params;
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		*n_args = 2;
		break;
	}
	/* linux_fremovexattr */
	case 220: {
		struct linux_fremovexattr_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		*n_args = 2;
		break;
	}
	/* linux_sys_futex */
	case 221: {
		struct linux_sys_futex_args *p = params;
		uarg[a++] = (intptr_t)p->uaddr; /* uint32_t * */
		iarg[a++] = p->op; /* l_int */
		uarg[a++] = p->val; /* uint32_t */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timespec * */
		uarg[a++] = (intptr_t)p->uaddr2; /* uint32_t * */
		uarg[a++] = p->val3; /* uint32_t */
		*n_args = 6;
		break;
	}
	/* linux_sched_setaffinity */
	case 222: {
		struct linux_sched_setaffinity_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->len; /* l_uint */
		uarg[a++] = (intptr_t)p->user_mask_ptr; /* l_ulong * */
		*n_args = 3;
		break;
	}
	/* linux_sched_getaffinity */
	case 223: {
		struct linux_sched_getaffinity_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->len; /* l_uint */
		uarg[a++] = (intptr_t)p->user_mask_ptr; /* l_ulong * */
		*n_args = 3;
		break;
	}
	/* linux_set_tid_address */
	case 232: {
		struct linux_set_tid_address_args *p = params;
		uarg[a++] = (intptr_t)p->tidptr; /* l_int * */
		*n_args = 1;
		break;
	}
	/* linux_fadvise64 */
	case 233: {
		struct linux_fadvise64_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->offset; /* l_loff_t */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->advice; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_exit_group */
	case 234: {
		struct linux_exit_group_args *p = params;
		iarg[a++] = p->error_code; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_lookup_dcookie */
	case 235: {
		*n_args = 0;
		break;
	}
	/* linux_epoll_create */
	case 236: {
		struct linux_epoll_create_args *p = params;
		iarg[a++] = p->size; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_epoll_ctl */
	case 237: {
		struct linux_epoll_ctl_args *p = params;
		iarg[a++] = p->epfd; /* l_int */
		iarg[a++] = p->op; /* l_int */
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->event; /* struct epoll_event * */
		*n_args = 4;
		break;
	}
	/* linux_epoll_wait */
	case 238: {
		struct linux_epoll_wait_args *p = params;
		iarg[a++] = p->epfd; /* l_int */
		uarg[a++] = (intptr_t)p->events; /* struct epoll_event * */
		iarg[a++] = p->maxevents; /* l_int */
		iarg[a++] = p->timeout; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_remap_file_pages */
	case 239: {
		*n_args = 0;
		break;
	}
	/* linux_timer_create */
	case 240: {
		struct linux_timer_create_args *p = params;
		iarg[a++] = p->clock_id; /* clockid_t */
		uarg[a++] = (intptr_t)p->evp; /* struct sigevent * */
		uarg[a++] = (intptr_t)p->timerid; /* l_timer_t * */
		*n_args = 3;
		break;
	}
	/* linux_timer_settime */
	case 241: {
		struct linux_timer_settime_args *p = params;
		iarg[a++] = p->timerid; /* l_timer_t */
		iarg[a++] = p->flags; /* l_int */
		uarg[a++] = (intptr_t)p->new; /* const struct itimerspec * */
		uarg[a++] = (intptr_t)p->old; /* struct itimerspec * */
		*n_args = 4;
		break;
	}
	/* linux_timer_gettime */
	case 242: {
		struct linux_timer_gettime_args *p = params;
		iarg[a++] = p->timerid; /* l_timer_t */
		uarg[a++] = (intptr_t)p->setting; /* struct itimerspec * */
		*n_args = 2;
		break;
	}
	/* linux_timer_getoverrun */
	case 243: {
		struct linux_timer_getoverrun_args *p = params;
		iarg[a++] = p->timerid; /* l_timer_t */
		*n_args = 1;
		break;
	}
	/* linux_timer_delete */
	case 244: {
		struct linux_timer_delete_args *p = params;
		iarg[a++] = p->timerid; /* l_timer_t */
		*n_args = 1;
		break;
	}
	/* linux_clock_settime */
	case 245: {
		struct linux_clock_settime_args *p = params;
		iarg[a++] = p->which; /* clockid_t */
		uarg[a++] = (intptr_t)p->tp; /* struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_clock_gettime */
	case 246: {
		struct linux_clock_gettime_args *p = params;
		iarg[a++] = p->which; /* clockid_t */
		uarg[a++] = (intptr_t)p->tp; /* struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_clock_getres */
	case 247: {
		struct linux_clock_getres_args *p = params;
		iarg[a++] = p->which; /* clockid_t */
		uarg[a++] = (intptr_t)p->tp; /* struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_clock_nanosleep */
	case 248: {
		struct linux_clock_nanosleep_args *p = params;
		iarg[a++] = p->which; /* clockid_t */
		iarg[a++] = p->flags; /* l_int */
		uarg[a++] = (intptr_t)p->rqtp; /* struct l_timespec * */
		uarg[a++] = (intptr_t)p->rmtp; /* struct l_timespec * */
		*n_args = 4;
		break;
	}
	/* linux_tgkill */
	case 250: {
		struct linux_tgkill_args *p = params;
		iarg[a++] = p->tgid; /* l_pid_t */
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->sig; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_utimes */
	case 251: {
		struct linux_utimes_args *p = params;
		uarg[a++] = (intptr_t)p->fname; /* char * */
		uarg[a++] = (intptr_t)p->tptr; /* struct l_timeval * */
		*n_args = 2;
		break;
	}
	/* linux_migrate_pages */
	case 258: {
		*n_args = 0;
		break;
	}
	/* linux_mbind */
	case 259: {
		*n_args = 0;
		break;
	}
	/* linux_get_mempolicy */
	case 260: {
		*n_args = 0;
		break;
	}
	/* linux_set_mempolicy */
	case 261: {
		*n_args = 0;
		break;
	}
	/* linux_mq_open */
	case 262: {
		struct linux_mq_open_args *p = params;
		uarg[a++] = (intptr_t)p->name; /* const char * */
		iarg[a++] = p->oflag; /* l_int */
		iarg[a++] = p->mode; /* l_mode_t */
		uarg[a++] = (intptr_t)p->attr; /* struct mq_attr * */
		*n_args = 4;
		break;
	}
	/* linux_mq_unlink */
	case 263: {
		struct linux_mq_unlink_args *p = params;
		uarg[a++] = (intptr_t)p->name; /* const char * */
		*n_args = 1;
		break;
	}
	/* linux_mq_timedsend */
	case 264: {
		struct linux_mq_timedsend_args *p = params;
		iarg[a++] = p->mqd; /* l_mqd_t */
		uarg[a++] = (intptr_t)p->msg_ptr; /* const char * */
		iarg[a++] = p->msg_len; /* l_size_t */
		iarg[a++] = p->msg_prio; /* l_uint */
		uarg[a++] = (intptr_t)p->abs_timeout; /* const struct l_timespec * */
		*n_args = 5;
		break;
	}
	/* linux_mq_timedreceive */
	case 265: {
		struct linux_mq_timedreceive_args *p = params;
		iarg[a++] = p->mqd; /* l_mqd_t */
		uarg[a++] = (intptr_t)p->msg_ptr; /* char * */
		iarg[a++] = p->msg_len; /* l_size_t */
		uarg[a++] = (intptr_t)p->msg_prio; /* l_uint * */
		uarg[a++] = (intptr_t)p->abs_timeout; /* const struct l_timespec * */
		*n_args = 5;
		break;
	}
	/* linux_mq_notify */
	case 266: {
		struct linux_mq_notify_args *p = params;
		iarg[a++] = p->mqd; /* l_mqd_t */
		uarg[a++] = (intptr_t)p->abs_timeout; /* const struct l_timespec * */
		*n_args = 2;
		break;
	}
	/* linux_mq_getsetattr */
	case 267: {
		struct linux_mq_getsetattr_args *p = params;
		iarg[a++] = p->mqd; /* l_mqd_t */
		uarg[a++] = (intptr_t)p->attr; /* const struct mq_attr * */
		uarg[a++] = (intptr_t)p->oattr; /* struct mq_attr * */
		*n_args = 3;
		break;
	}
	/* linux_kexec_load */
	case 268: {
		*n_args = 0;
		break;
	}
	/* linux_add_key */
	case 269: {
		*n_args = 0;
		break;
	}
	/* linux_request_key */
	case 270: {
		*n_args = 0;
		break;
	}
	/* linux_keyctl */
	case 271: {
		*n_args = 0;
		break;
	}
	/* linux_waitid */
	case 272: {
		struct linux_waitid_args *p = params;
		iarg[a++] = p->idtype; /* l_int */
		iarg[a++] = p->id; /* l_pid_t */
		uarg[a++] = (intptr_t)p->info; /* l_siginfo_t * */
		iarg[a++] = p->options; /* l_int */
		uarg[a++] = (intptr_t)p->rusage; /* struct rusage * */
		*n_args = 5;
		break;
	}
	/* linux_ioprio_set */
	case 273: {
		*n_args = 0;
		break;
	}
	/* linux_ioprio_get */
	case 274: {
		*n_args = 0;
		break;
	}
	/* linux_inotify_add_watch */
	case 276: {
		*n_args = 0;
		break;
	}
	/* linux_inotify_rm_watch */
	case 277: {
		*n_args = 0;
		break;
	}
	/* linux_pselect6 */
	case 280: {
		struct linux_pselect6_args *p = params;
		iarg[a++] = p->nfds; /* l_int */
		uarg[a++] = (intptr_t)p->readfds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->writefds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->exceptfds; /* l_fd_set * */
		uarg[a++] = (intptr_t)p->tsp; /* struct l_timespec * */
		uarg[a++] = (intptr_t)p->sig; /* l_uintptr_t * */
		*n_args = 6;
		break;
	}
	/* linux_ppoll */
	case 281: {
		struct linux_ppoll_args *p = params;
		uarg[a++] = (intptr_t)p->fds; /* struct pollfd * */
		iarg[a++] = p->nfds; /* l_uint */
		uarg[a++] = (intptr_t)p->tsp; /* struct l_timespec * */
		uarg[a++] = (intptr_t)p->sset; /* l_sigset_t * */
		iarg[a++] = p->ssize; /* l_size_t */
		*n_args = 5;
		break;
	}
	/* linux_unshare */
	case 282: {
		*n_args = 0;
		break;
	}
	/* linux_splice */
	case 283: {
		struct linux_splice_args *p = params;
		iarg[a++] = p->fd_in; /* int */
		uarg[a++] = (intptr_t)p->off_in; /* l_loff_t * */
		iarg[a++] = p->fd_out; /* int */
		uarg[a++] = (intptr_t)p->off_out; /* l_loff_t * */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 6;
		break;
	}
	/* linux_tee */
	case 284: {
		*n_args = 0;
		break;
	}
	/* linux_vmsplice */
	case 285: {
		*n_args = 0;
		break;
	}
	/* linux_openat */
	case 286: {
		struct linux_openat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->flags; /* l_int */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 4;
		break;
	}
	/* linux_mkdirat */
	case 287: {
		struct linux_mkdirat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->pathname; /* const char * */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 3;
		break;
	}
	/* linux_mknodat */
	case 288: {
		struct linux_mknodat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->mode; /* l_mode_t */
		iarg[a++] = p->dev; /* l_uint */
		*n_args = 4;
		break;
	}
	/* linux_fchownat */
	case 289: {
		struct linux_fchownat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->uid; /* l_uid_t */
		iarg[a++] = p->gid; /* l_gid_t */
		iarg[a++] = p->flag; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_futimesat */
	case 290: {
		struct linux_futimesat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* char * */
		uarg[a++] = (intptr_t)p->utimes; /* struct l_timeval * */
		*n_args = 3;
		break;
	}
	/* linux_newfstatat */
	case 291: {
		struct linux_newfstatat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->pathname; /* char * */
		uarg[a++] = (intptr_t)p->statbuf; /* struct l_stat64 * */
		iarg[a++] = p->flag; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_unlinkat */
	case 292: {
		struct linux_unlinkat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->pathname; /* const char * */
		iarg[a++] = p->flag; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_renameat */
	case 293: {
		struct linux_renameat_args *p = params;
		iarg[a++] = p->olddfd; /* l_int */
		uarg[a++] = (intptr_t)p->oldname; /* const char * */
		iarg[a++] = p->newdfd; /* l_int */
		uarg[a++] = (intptr_t)p->newname; /* const char * */
		*n_args = 4;
		break;
	}
	/* linux_linkat */
	case 294: {
		struct linux_linkat_args *p = params;
		iarg[a++] = p->olddfd; /* l_int */
		uarg[a++] = (intptr_t)p->oldname; /* const char * */
		iarg[a++] = p->newdfd; /* l_int */
		uarg[a++] = (intptr_t)p->newname; /* const char * */
		iarg[a++] = p->flag; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_symlinkat */
	case 295: {
		struct linux_symlinkat_args *p = params;
		uarg[a++] = (intptr_t)p->oldname; /* const char * */
		iarg[a++] = p->newdfd; /* l_int */
		uarg[a++] = (intptr_t)p->newname; /* const char * */
		*n_args = 3;
		break;
	}
	/* linux_readlinkat */
	case 296: {
		struct linux_readlinkat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->path; /* const char * */
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->bufsiz; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_fchmodat */
	case 297: {
		struct linux_fchmodat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->mode; /* l_mode_t */
		*n_args = 3;
		break;
	}
	/* linux_faccessat */
	case 298: {
		struct linux_faccessat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->amode; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_get_robust_list */
	case 299: {
		struct linux_get_robust_list_args *p = params;
		iarg[a++] = p->pid; /* l_int */
		uarg[a++] = (intptr_t)p->head; /* struct linux_robust_list_head ** */
		uarg[a++] = (intptr_t)p->len; /* l_size_t * */
		*n_args = 3;
		break;
	}
	/* linux_set_robust_list */
	case 300: {
		struct linux_set_robust_list_args *p = params;
		uarg[a++] = (intptr_t)p->head; /* struct linux_robust_list_head * */
		iarg[a++] = p->len; /* l_size_t */
		*n_args = 2;
		break;
	}
	/* linux_move_pages */
	case 301: {
		*n_args = 0;
		break;
	}
	/* linux_getcpu */
	case 302: {
		struct linux_getcpu_args *p = params;
		uarg[a++] = (intptr_t)p->cpu; /* l_uint * */
		uarg[a++] = (intptr_t)p->node; /* l_uint * */
		uarg[a++] = (intptr_t)p->cache; /* void * */
		*n_args = 3;
		break;
	}
	/* linux_epoll_pwait */
	case 303: {
		struct linux_epoll_pwait_args *p = params;
		iarg[a++] = p->epfd; /* l_int */
		uarg[a++] = (intptr_t)p->events; /* struct epoll_event * */
		iarg[a++] = p->maxevents; /* l_int */
		iarg[a++] = p->timeout; /* l_int */
		uarg[a++] = (intptr_t)p->mask; /* l_sigset_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 6;
		break;
	}
	/* linux_utimensat */
	case 304: {
		struct linux_utimensat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->pathname; /* const char * */
		uarg[a++] = (intptr_t)p->times; /* const struct l_timespec * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_timerfd_create */
	case 306: {
		struct linux_timerfd_create_args *p = params;
		iarg[a++] = p->clockid; /* l_int */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_eventfd */
	case 307: {
		struct linux_eventfd_args *p = params;
		iarg[a++] = p->initval; /* l_uint */
		*n_args = 1;
		break;
	}
	/* linux_sync_file_range */
	case 308: {
		struct linux_sync_file_range_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->offset; /* l_loff_t */
		iarg[a++] = p->nbytes; /* l_loff_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 4;
		break;
	}
	/* linux_fallocate */
	case 309: {
		struct linux_fallocate_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->mode; /* l_int */
		iarg[a++] = p->offset; /* l_loff_t */
		iarg[a++] = p->len; /* l_loff_t */
		*n_args = 4;
		break;
	}
	/* linux_timerfd_settime */
	case 311: {
		struct linux_timerfd_settime_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->flags; /* l_int */
		uarg[a++] = (intptr_t)p->new_value; /* const struct l_itimerspec * */
		uarg[a++] = (intptr_t)p->old_value; /* struct l_itimerspec * */
		*n_args = 4;
		break;
	}
	/* linux_timerfd_gettime */
	case 312: {
		struct linux_timerfd_gettime_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->old_value; /* struct l_itimerspec * */
		*n_args = 2;
		break;
	}
	/* linux_signalfd4 */
	case 313: {
		*n_args = 0;
		break;
	}
	/* linux_eventfd2 */
	case 314: {
		struct linux_eventfd2_args *p = params;
		iarg[a++] = p->initval; /* l_uint */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_epoll_create1 */
	case 315: {
		struct linux_epoll_create1_args *p = params;
		iarg[a++] = p->flags; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_dup3 */
	case 316: {
		struct linux_dup3_args *p = params;
		iarg[a++] = p->oldfd; /* l_uint */
		iarg[a++] = p->newfd; /* l_uint */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_pipe2 */
	case 317: {
		struct linux_pipe2_args *p = params;
		uarg[a++] = (intptr_t)p->pipefds; /* l_int * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_inotify_init1 */
	case 318: {
		struct linux_inotify_init1_args *p = params;
		iarg[a++] = p->flags; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_perf_event_open */
	case 319: {
		*n_args = 0;
		break;
	}
	/* linux_preadv */
	case 320: {
		struct linux_preadv_args *p = params;
		iarg[a++] = p->fd; /* l_ulong */
		uarg[a++] = (intptr_t)p->vec; /* struct iovec * */
		iarg[a++] = p->vlen; /* l_ulong */
		iarg[a++] = p->pos_l; /* l_ulong */
		iarg[a++] = p->pos_h; /* l_ulong */
		*n_args = 5;
		break;
	}
	/* linux_pwritev */
	case 321: {
		struct linux_pwritev_args *p = params;
		iarg[a++] = p->fd; /* l_ulong */
		uarg[a++] = (intptr_t)p->vec; /* struct iovec * */
		iarg[a++] = p->vlen; /* l_ulong */
		iarg[a++] = p->pos_l; /* l_ulong */
		iarg[a++] = p->pos_h; /* l_ulong */
		*n_args = 5;
		break;
	}
	/* linux_rt_tgsigqueueinfo */
	case 322: {
		struct linux_rt_tgsigqueueinfo_args *p = params;
		iarg[a++] = p->tgid; /* l_pid_t */
		iarg[a++] = p->tid; /* l_pid_t */
		iarg[a++] = p->sig; /* l_int */
		uarg[a++] = (intptr_t)p->uinfo; /* l_siginfo_t * */
		*n_args = 4;
		break;
	}
	/* linux_fanotify_init */
	case 323: {
		*n_args = 0;
		break;
	}
	/* linux_fanotify_mark */
	case 324: {
		*n_args = 0;
		break;
	}
	/* linux_prlimit64 */
	case 325: {
		struct linux_prlimit64_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		iarg[a++] = p->resource; /* l_uint */
		uarg[a++] = (intptr_t)p->new; /* struct rlimit * */
		uarg[a++] = (intptr_t)p->old; /* struct rlimit * */
		*n_args = 4;
		break;
	}
	/* linux_socket */
	case 326: {
		struct linux_socket_args *p = params;
		iarg[a++] = p->domain; /* l_int */
		iarg[a++] = p->type; /* l_int */
		iarg[a++] = p->protocol; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_bind */
	case 327: {
		struct linux_bind_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* l_uintptr_t */
		iarg[a++] = p->namelen; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_connect */
	case 328: {
		struct linux_connect_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* l_uintptr_t */
		iarg[a++] = p->namelen; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_listen */
	case 329: {
		struct linux_listen_args *p = params;
		iarg[a++] = p->s; /* l_int */
		iarg[a++] = p->backlog; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_accept */
	case 330: {
		struct linux_accept_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->addr; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->namelen; /* l_uintptr_t */
		*n_args = 3;
		break;
	}
	/* linux_getsockname */
	case 331: {
		struct linux_getsockname_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->addr; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->namelen; /* l_uintptr_t */
		*n_args = 3;
		break;
	}
	/* linux_getpeername */
	case 332: {
		struct linux_getpeername_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->addr; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->namelen; /* l_uintptr_t */
		*n_args = 3;
		break;
	}
	/* linux_socketpair */
	case 333: {
		struct linux_socketpair_args *p = params;
		iarg[a++] = p->domain; /* l_int */
		iarg[a++] = p->type; /* l_int */
		iarg[a++] = p->protocol; /* l_int */
		uarg[a++] = (intptr_t)p->rsv; /* l_uintptr_t */
		*n_args = 4;
		break;
	}
	/* linux_sendto */
	case 335: {
		struct linux_sendto_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->msg; /* l_uintptr_t */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->flags; /* l_uint */
		uarg[a++] = (intptr_t)p->to; /* l_uintptr_t */
		iarg[a++] = p->tolen; /* l_int */
		*n_args = 6;
		break;
	}
	/* linux_recvfrom */
	case 337: {
		struct linux_recvfrom_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->buf; /* l_uintptr_t */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->flags; /* l_uint */
		uarg[a++] = (intptr_t)p->from; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->fromlen; /* l_uintptr_t */
		*n_args = 6;
		break;
	}
	/* linux_shutdown */
	case 338: {
		struct linux_shutdown_args *p = params;
		iarg[a++] = p->s; /* l_int */
		iarg[a++] = p->how; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_setsockopt */
	case 339: {
		struct linux_setsockopt_args *p = params;
		iarg[a++] = p->s; /* l_int */
		iarg[a++] = p->level; /* l_int */
		iarg[a++] = p->optname; /* l_int */
		uarg[a++] = (intptr_t)p->optval; /* l_uintptr_t */
		iarg[a++] = p->optlen; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_getsockopt */
	case 340: {
		struct linux_getsockopt_args *p = params;
		iarg[a++] = p->s; /* l_int */
		iarg[a++] = p->level; /* l_int */
		iarg[a++] = p->optname; /* l_int */
		uarg[a++] = (intptr_t)p->optval; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->optlen; /* l_uintptr_t */
		*n_args = 5;
		break;
	}
	/* linux_sendmsg */
	case 341: {
		struct linux_sendmsg_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->msg; /* l_uintptr_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_recvmsg */
	case 342: {
		struct linux_recvmsg_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->msg; /* l_uintptr_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_recvmmsg */
	case 343: {
		struct linux_recvmmsg_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->msg; /* struct l_mmsghdr * */
		iarg[a++] = p->vlen; /* l_uint */
		iarg[a++] = p->flags; /* l_uint */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timespec * */
		*n_args = 5;
		break;
	}
	/* linux_accept4 */
	case 344: {
		struct linux_accept4_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->addr; /* l_uintptr_t */
		uarg[a++] = (intptr_t)p->namelen; /* l_uintptr_t */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_name_to_handle_at */
	case 345: {
		struct linux_name_to_handle_at_args *p = params;
		iarg[a++] = p->dirfd; /* l_int */
		uarg[a++] = (intptr_t)p->name; /* const char * */
		uarg[a++] = (intptr_t)p->handle; /* struct l_file_handle * */
		uarg[a++] = (intptr_t)p->mnt_id; /* l_int * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_open_by_handle_at */
	case 346: {
		struct linux_open_by_handle_at_args *p = params;
		iarg[a++] = p->mountdirfd; /* l_int */
		uarg[a++] = (intptr_t)p->handle; /* struct l_file_handle * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_clock_adjtime */
	case 347: {
		*n_args = 0;
		break;
	}
	/* linux_syncfs */
	case 348: {
		struct linux_syncfs_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_sendmmsg */
	case 349: {
		struct linux_sendmmsg_args *p = params;
		iarg[a++] = p->s; /* l_int */
		uarg[a++] = (intptr_t)p->msg; /* struct l_mmsghdr * */
		iarg[a++] = p->vlen; /* l_uint */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 4;
		break;
	}
	/* linux_setns */
	case 350: {
		struct linux_setns_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		iarg[a++] = p->nstype; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_process_vm_readv */
	case 351: {
		struct linux_process_vm_readv_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->lvec; /* const struct iovec * */
		iarg[a++] = p->liovcnt; /* l_ulong */
		uarg[a++] = (intptr_t)p->rvec; /* const struct iovec * */
		iarg[a++] = p->riovcnt; /* l_ulong */
		iarg[a++] = p->flags; /* l_ulong */
		*n_args = 6;
		break;
	}
	/* linux_process_vm_writev */
	case 352: {
		struct linux_process_vm_writev_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->lvec; /* const struct iovec * */
		iarg[a++] = p->liovcnt; /* l_ulong */
		uarg[a++] = (intptr_t)p->rvec; /* const struct iovec * */
		iarg[a++] = p->riovcnt; /* l_ulong */
		iarg[a++] = p->flags; /* l_ulong */
		*n_args = 6;
		break;
	}
	/* linux_finit_module */
	case 353: {
		struct linux_finit_module_args *p = params;
		iarg[a++] = p->fd; /* l_int */
		uarg[a++] = (intptr_t)p->uargs; /* const char * */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_kcmp */
	case 354: {
		struct linux_kcmp_args *p = params;
		iarg[a++] = p->pid1; /* l_pid_t */
		iarg[a++] = p->pid2; /* l_pid_t */
		iarg[a++] = p->type; /* l_int */
		iarg[a++] = p->idx1; /* l_ulong */
		iarg[a++] = p->idx; /* l_ulong */
		*n_args = 5;
		break;
	}
	/* linux_sched_setattr */
	case 355: {
		struct linux_sched_setattr_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->attr; /* void * */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_sched_getattr */
	case 356: {
		struct linux_sched_getattr_args *p = params;
		iarg[a++] = p->pid; /* l_pid_t */
		uarg[a++] = (intptr_t)p->attr; /* void * */
		iarg[a++] = p->size; /* l_uint */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 4;
		break;
	}
	/* linux_renameat2 */
	case 357: {
		struct linux_renameat2_args *p = params;
		iarg[a++] = p->olddfd; /* l_int */
		uarg[a++] = (intptr_t)p->oldname; /* const char * */
		iarg[a++] = p->newdfd; /* l_int */
		uarg[a++] = (intptr_t)p->newname; /* const char * */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 5;
		break;
	}
	/* linux_seccomp */
	case 358: {
		struct linux_seccomp_args *p = params;
		iarg[a++] = p->op; /* l_uint */
		iarg[a++] = p->flags; /* l_uint */
		uarg[a++] = (intptr_t)p->uargs; /* const char * */
		*n_args = 3;
		break;
	}
	/* linux_getrandom */
	case 359: {
		struct linux_getrandom_args *p = params;
		uarg[a++] = (intptr_t)p->buf; /* char * */
		iarg[a++] = p->count; /* l_size_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_memfd_create */
	case 360: {
		struct linux_memfd_create_args *p = params;
		uarg[a++] = (intptr_t)p->uname_ptr; /* const char * */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 2;
		break;
	}
	/* linux_bpf */
	case 361: {
		struct linux_bpf_args *p = params;
		iarg[a++] = p->cmd; /* l_int */
		uarg[a++] = (intptr_t)p->attr; /* void * */
		iarg[a++] = p->size; /* l_uint */
		*n_args = 3;
		break;
	}
	/* linux_execveat */
	case 362: {
		struct linux_execveat_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		uarg[a++] = (intptr_t)p->argv; /* const char ** */
		uarg[a++] = (intptr_t)p->envp; /* const char ** */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_userfaultfd */
	case 364: {
		struct linux_userfaultfd_args *p = params;
		iarg[a++] = p->flags; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_membarrier */
	case 365: {
		struct linux_membarrier_args *p = params;
		iarg[a++] = p->cmd; /* l_int */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_mlock2 */
	case 378: {
		struct linux_mlock2_args *p = params;
		iarg[a++] = p->start; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_copy_file_range */
	case 379: {
		struct linux_copy_file_range_args *p = params;
		iarg[a++] = p->fd_in; /* l_int */
		uarg[a++] = (intptr_t)p->off_in; /* l_loff_t * */
		iarg[a++] = p->fd_out; /* l_int */
		uarg[a++] = (intptr_t)p->off_out; /* l_loff_t * */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 6;
		break;
	}
	/* linux_preadv2 */
	case 380: {
		struct linux_preadv2_args *p = params;
		iarg[a++] = p->fd; /* l_ulong */
		uarg[a++] = (intptr_t)p->vec; /* const struct iovec * */
		iarg[a++] = p->vlen; /* l_ulong */
		iarg[a++] = p->pos_l; /* l_ulong */
		iarg[a++] = p->pos_h; /* l_ulong */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 6;
		break;
	}
	/* linux_pwritev2 */
	case 381: {
		struct linux_pwritev2_args *p = params;
		iarg[a++] = p->fd; /* l_ulong */
		uarg[a++] = (intptr_t)p->vec; /* const struct iovec * */
		iarg[a++] = p->vlen; /* l_ulong */
		iarg[a++] = p->pos_l; /* l_ulong */
		iarg[a++] = p->pos_h; /* l_ulong */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 6;
		break;
	}
	/* linux_statx */
	case 383: {
		struct linux_statx_args *p = params;
		iarg[a++] = p->dirfd; /* l_int */
		uarg[a++] = (intptr_t)p->pathname; /* const char * */
		iarg[a++] = p->flags; /* l_uint */
		iarg[a++] = p->mask; /* l_uint */
		uarg[a++] = (intptr_t)p->statxbuf; /* void * */
		*n_args = 5;
		break;
	}
	/* linux_pkey_alloc */
	case 384: {
		struct linux_pkey_alloc_args *p = params;
		iarg[a++] = p->flags; /* l_ulong */
		iarg[a++] = p->init_val; /* l_ulong */
		*n_args = 2;
		break;
	}
	/* linux_pkey_free */
	case 385: {
		struct linux_pkey_free_args *p = params;
		iarg[a++] = p->pkey; /* l_int */
		*n_args = 1;
		break;
	}
	/* linux_pkey_mprotect */
	case 386: {
		struct linux_pkey_mprotect_args *p = params;
		iarg[a++] = p->start; /* l_ulong */
		iarg[a++] = p->len; /* l_size_t */
		iarg[a++] = p->prot; /* l_ulong */
		iarg[a++] = p->pkey; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_rseq */
	case 387: {
		struct linux_rseq_args *p = params;
		uarg[a++] = (intptr_t)p->rseq; /* struct linux_rseq * */
		uarg[a++] = p->rseq_len; /* uint32_t */
		iarg[a++] = p->flags; /* l_int */
		uarg[a++] = p->sig; /* uint32_t */
		*n_args = 4;
		break;
	}
	/* linux_io_pgetevents */
	case 388: {
		*n_args = 0;
		break;
	}
	/* linux_semtimedop */
	case 392: {
		struct linux_semtimedop_args *p = params;
		iarg[a++] = p->semid; /* l_int */
		uarg[a++] = (intptr_t)p->tsops; /* struct sembuf * */
		iarg[a++] = p->nsops; /* l_size_t */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timespec * */
		*n_args = 4;
		break;
	}
	/* linux_semget */
	case 393: {
		struct linux_semget_args *p = params;
		iarg[a++] = p->key; /* l_key_t */
		iarg[a++] = p->nsems; /* l_int */
		iarg[a++] = p->semflg; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_semctl */
	case 394: {
		struct linux_semctl_args *p = params;
		iarg[a++] = p->semid; /* l_int */
		iarg[a++] = p->semnum; /* l_int */
		iarg[a++] = p->cmd; /* l_int */
		uarg[a++] = p->arg.buf; /* union l_semun */
		*n_args = 4;
		break;
	}
	/* linux_shmget */
	case 395: {
		struct linux_shmget_args *p = params;
		iarg[a++] = p->key; /* l_key_t */
		iarg[a++] = p->size; /* l_size_t */
		iarg[a++] = p->shmflg; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_shmctl */
	case 396: {
		struct linux_shmctl_args *p = params;
		iarg[a++] = p->shmid; /* l_int */
		iarg[a++] = p->cmd; /* l_int */
		uarg[a++] = (intptr_t)p->buf; /* struct l_shmid_ds * */
		*n_args = 3;
		break;
	}
	/* linux_shmat */
	case 397: {
		struct linux_shmat_args *p = params;
		iarg[a++] = p->shmid; /* l_int */
		uarg[a++] = (intptr_t)p->shmaddr; /* char * */
		iarg[a++] = p->shmflg; /* l_int */
		*n_args = 3;
		break;
	}
	/* linux_shmdt */
	case 398: {
		struct linux_shmdt_args *p = params;
		uarg[a++] = (intptr_t)p->shmaddr; /* char * */
		*n_args = 1;
		break;
	}
	/* linux_msgget */
	case 399: {
		struct linux_msgget_args *p = params;
		iarg[a++] = p->key; /* l_key_t */
		iarg[a++] = p->msgflg; /* l_int */
		*n_args = 2;
		break;
	}
	/* linux_msgsnd */
	case 400: {
		struct linux_msgsnd_args *p = params;
		iarg[a++] = p->msqid; /* l_int */
		uarg[a++] = (intptr_t)p->msgp; /* struct l_msgbuf * */
		iarg[a++] = p->msgsz; /* l_size_t */
		iarg[a++] = p->msgflg; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_msgrcv */
	case 401: {
		struct linux_msgrcv_args *p = params;
		iarg[a++] = p->msqid; /* l_int */
		uarg[a++] = (intptr_t)p->msgp; /* struct l_msgbuf * */
		iarg[a++] = p->msgsz; /* l_size_t */
		iarg[a++] = p->msgtyp; /* l_long */
		iarg[a++] = p->msgflg; /* l_int */
		*n_args = 5;
		break;
	}
	/* linux_msgctl */
	case 402: {
		struct linux_msgctl_args *p = params;
		iarg[a++] = p->msqid; /* l_int */
		iarg[a++] = p->cmd; /* l_int */
		uarg[a++] = (intptr_t)p->buf; /* struct l_msqid_ds * */
		*n_args = 3;
		break;
	}
	/* linux_pidfd_send_signal */
	case 424: {
		struct linux_pidfd_send_signal_args *p = params;
		iarg[a++] = p->pidfd; /* l_int */
		iarg[a++] = p->sig; /* l_int */
		uarg[a++] = (intptr_t)p->info; /* l_siginfo_t * */
		iarg[a++] = p->flags; /* l_uint */
		*n_args = 4;
		break;
	}
	/* linux_io_uring_setup */
	case 425: {
		*n_args = 0;
		break;
	}
	/* linux_io_uring_enter */
	case 426: {
		*n_args = 0;
		break;
	}
	/* linux_io_uring_register */
	case 427: {
		*n_args = 0;
		break;
	}
	/* linux_open_tree */
	case 428: {
		*n_args = 0;
		break;
	}
	/* linux_move_mount */
	case 429: {
		*n_args = 0;
		break;
	}
	/* linux_fsopen */
	case 430: {
		*n_args = 0;
		break;
	}
	/* linux_fsconfig */
	case 431: {
		*n_args = 0;
		break;
	}
	/* linux_fsmount */
	case 432: {
		*n_args = 0;
		break;
	}
	/* linux_fspick */
	case 433: {
		*n_args = 0;
		break;
	}
	/* linux_pidfd_open */
	case 434: {
		*n_args = 0;
		break;
	}
	/* linux_clone3 */
	case 435: {
		struct linux_clone3_args *p = params;
		uarg[a++] = (intptr_t)p->uargs; /* struct l_user_clone_args * */
		iarg[a++] = p->usize; /* l_size_t */
		*n_args = 2;
		break;
	}
	/* linux_close_range */
	case 436: {
		*n_args = 0;
		break;
	}
	/* linux_openat2 */
	case 437: {
		*n_args = 0;
		break;
	}
	/* linux_pidfd_getfd */
	case 438: {
		*n_args = 0;
		break;
	}
	/* linux_faccessat2 */
	case 439: {
		struct linux_faccessat2_args *p = params;
		iarg[a++] = p->dfd; /* l_int */
		uarg[a++] = (intptr_t)p->filename; /* const char * */
		iarg[a++] = p->amode; /* l_int */
		iarg[a++] = p->flags; /* l_int */
		*n_args = 4;
		break;
	}
	/* linux_process_madvise */
	case 440: {
		*n_args = 0;
		break;
	}
	/* linux_epoll_pwait2 */
	case 441: {
		struct linux_epoll_pwait2_args *p = params;
		iarg[a++] = p->epfd; /* l_int */
		uarg[a++] = (intptr_t)p->events; /* struct epoll_event * */
		iarg[a++] = p->maxevents; /* l_int */
		uarg[a++] = (intptr_t)p->timeout; /* struct l_timespec * */
		uarg[a++] = (intptr_t)p->mask; /* l_sigset_t * */
		iarg[a++] = p->sigsetsize; /* l_size_t */
		*n_args = 6;
		break;
	}
	/* linux_mount_setattr */
	case 442: {
		*n_args = 0;
		break;
	}
	default:
		*n_args = 0;
		break;
	};
}
static void
systrace_entry_setargdesc(int sysnum, int ndx, char *desc, size_t descsz)
{
	const char *p = NULL;
	switch (sysnum) {
#define	nosys	linux_nosys
	/* linux_exit */
	case 1:
		switch (ndx) {
		case 0:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* linux_fork */
	case 2:
		break;
	/* read */
	case 3:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* write */
	case 4:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_open */
	case 5:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* close */
	case 6:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_creat */
	case 8:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_link */
	case 9:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_unlink */
	case 10:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_execve */
	case 11:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char **";
			break;
		case 2:
			p = "userland char **";
			break;
		default:
			break;
		};
		break;
	/* linux_chdir */
	case 12:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_time */
	case 13:
		switch (ndx) {
		case 0:
			p = "userland l_time_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_mknod */
	case 14:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_mode_t";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_chmod */
	case 15:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_lchown */
	case 16:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_uid_t";
			break;
		case 2:
			p = "l_gid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_lseek */
	case 19:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_off_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_getpid */
	case 20:
		break;
	/* linux_mount */
	case 21:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* linux_umount */
	case 22:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* setuid */
	case 23:
		switch (ndx) {
		case 0:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getuid */
	case 24:
		break;
	/* linux_ptrace */
	case 26:
		switch (ndx) {
		case 0:
			p = "l_long";
			break;
		case 1:
			p = "l_long";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_alarm */
	case 27:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_pause */
	case 29:
		break;
	/* linux_utime */
	case 30:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland struct l_utimbuf *";
			break;
		default:
			break;
		};
		break;
	/* linux_access */
	case 33:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* sync */
	case 36:
		break;
	/* linux_kill */
	case 37:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_rename */
	case 38:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_mkdir */
	case 39:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rmdir */
	case 40:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* dup */
	case 41:
		switch (ndx) {
		case 0:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* linux_pipe */
	case 42:
		switch (ndx) {
		case 0:
			p = "userland l_int *";
			break;
		default:
			break;
		};
		break;
	/* linux_times */
	case 43:
		switch (ndx) {
		case 0:
			p = "userland struct l_times_argv *";
			break;
		default:
			break;
		};
		break;
	/* linux_brk */
	case 45:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* setgid */
	case 46:
		switch (ndx) {
		case 0:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getgid */
	case 47:
		break;
	/* geteuid */
	case 49:
		break;
	/* getegid */
	case 50:
		break;
	/* acct */
	case 51:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_ioctl */
	case 54:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_fcntl */
	case 55:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* setpgid */
	case 57:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* umask */
	case 60:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* chroot */
	case 61:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_ustat */
	case 62:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland struct l_ustat *";
			break;
		default:
			break;
		};
		break;
	/* dup2 */
	case 63:
		switch (ndx) {
		case 0:
			p = "u_int";
			break;
		case 1:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* linux_getppid */
	case 64:
		break;
	/* getpgrp */
	case 65:
		break;
	/* setsid */
	case 66:
		break;
	/* setreuid */
	case 70:
		switch (ndx) {
		case 0:
			p = "uid_t";
			break;
		case 1:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* setregid */
	case 71:
		switch (ndx) {
		case 0:
			p = "gid_t";
			break;
		case 1:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_sethostname */
	case 74:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_setrlimit */
	case 75:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland struct l_rlimit *";
			break;
		default:
			break;
		};
		break;
	/* linux_getrlimit */
	case 76:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland struct l_rlimit *";
			break;
		default:
			break;
		};
		break;
	/* getrusage */
	case 77:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct rusage *";
			break;
		default:
			break;
		};
		break;
	/* gettimeofday */
	case 78:
		switch (ndx) {
		case 0:
			p = "userland struct l_timeval *";
			break;
		case 1:
			p = "userland struct timezone *";
			break;
		default:
			break;
		};
		break;
	/* settimeofday */
	case 79:
		switch (ndx) {
		case 0:
			p = "userland struct l_timeval *";
			break;
		case 1:
			p = "userland struct timezone *";
			break;
		default:
			break;
		};
		break;
	/* linux_getgroups */
	case 80:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_gid_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_setgroups */
	case 81:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_gid_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_select */
	case 82:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_fd_set *";
			break;
		case 2:
			p = "userland l_fd_set *";
			break;
		case 3:
			p = "userland l_fd_set *";
			break;
		case 4:
			p = "userland struct l_timeval *";
			break;
		default:
			break;
		};
		break;
	/* linux_symlink */
	case 83:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_readlink */
	case 85:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* swapon */
	case 87:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_reboot */
	case 88:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_uint";
			break;
		case 3:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* linux_mmap */
	case 90:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_ulong";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* munmap */
	case 91:
		switch (ndx) {
		case 0:
			p = "userland void *";
			break;
		case 1:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_truncate */
	case 92:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_long";
			break;
		default:
			break;
		};
		break;
	/* linux_ftruncate */
	case 93:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* fchmod */
	case 94:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fchown */
	case 95:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_getpriority */
	case 96:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* setpriority */
	case 97:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_statfs */
	case 99:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland struct l_statfs_buf *";
			break;
		default:
			break;
		};
		break;
	/* linux_fstatfs */
	case 100:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland struct l_statfs_buf *";
			break;
		default:
			break;
		};
		break;
	/* linux_ioperm */
	case 101:
		break;
	/* linux_syslog */
	case 103:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_setitimer */
	case 104:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_itimerval *";
			break;
		case 2:
			p = "userland struct l_itimerval *";
			break;
		default:
			break;
		};
		break;
	/* linux_getitimer */
	case 105:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_itimerval *";
			break;
		default:
			break;
		};
		break;
	/* linux_newstat */
	case 106:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland struct l_newstat *";
			break;
		default:
			break;
		};
		break;
	/* linux_newlstat */
	case 107:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland struct l_newstat *";
			break;
		default:
			break;
		};
		break;
	/* linux_newfstat */
	case 108:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland struct l_newstat *";
			break;
		default:
			break;
		};
		break;
	/* linux_iopl */
	case 110:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_vhangup */
	case 111:
		break;
	/* linux_wait4 */
	case 114:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland l_int *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland struct rusage *";
			break;
		default:
			break;
		};
		break;
	/* linux_swapoff */
	case 115:
		break;
	/* linux_sysinfo */
	case 116:
		switch (ndx) {
		case 0:
			p = "userland struct l_sysinfo *";
			break;
		default:
			break;
		};
		break;
	/* fsync */
	case 118:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_clone */
	case 120:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_ulong";
			break;
		case 2:
			p = "userland l_int *";
			break;
		case 3:
			p = "userland l_int *";
			break;
		case 4:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_setdomainname */
	case 121:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_newuname */
	case 122:
		switch (ndx) {
		case 0:
			p = "userland struct l_new_utsname *";
			break;
		default:
			break;
		};
		break;
	/* linux_modify_ldt */
	case 123:
		break;
	/* linux_adjtimex */
	case 124:
		break;
	/* linux_mprotect */
	case 125:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_init_module */
	case 128:
		break;
	/* linux_delete_module */
	case 129:
		break;
	/* linux_quotactl */
	case 131:
		break;
	/* getpgid */
	case 132:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* fchdir */
	case 133:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_personality */
	case 136:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_setfsuid */
	case 138:
		switch (ndx) {
		case 0:
			p = "l_uid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_setfsgid */
	case 139:
		switch (ndx) {
		case 0:
			p = "l_gid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getdents */
	case 141:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* flock */
	case 143:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* linux_msync */
	case 144:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* readv */
	case 145:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec *";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* writev */
	case 146:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland struct iovec *";
			break;
		case 2:
			p = "u_int";
			break;
		default:
			break;
		};
		break;
	/* linux_getsid */
	case 147:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_fdatasync */
	case 148:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_sysctl */
	case 149:
		switch (ndx) {
		case 0:
			p = "userland struct l___sysctl_args *";
			break;
		default:
			break;
		};
		break;
	/* mlock */
	case 150:
		switch (ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* munlock */
	case 151:
		switch (ndx) {
		case 0:
			p = "userland const void *";
			break;
		case 1:
			p = "size_t";
			break;
		default:
			break;
		};
		break;
	/* mlockall */
	case 152:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* munlockall */
	case 153:
		break;
	/* linux_sched_setparam */
	case 154:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_getparam */
	case 155:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_setscheduler */
	case 156:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland struct sched_param *";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_getscheduler */
	case 157:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		default:
			break;
		};
		break;
	/* sched_yield */
	case 158:
		break;
	/* linux_sched_get_priority_max */
	case 159:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_get_priority_min */
	case 160:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_rr_get_interval */
	case 161:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_nanosleep */
	case 162:
		switch (ndx) {
		case 0:
			p = "userland const struct l_timespec *";
			break;
		case 1:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_mremap */
	case 163:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_ulong";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* setresuid */
	case 164:
		switch (ndx) {
		case 0:
			p = "uid_t";
			break;
		case 1:
			p = "uid_t";
			break;
		case 2:
			p = "uid_t";
			break;
		default:
			break;
		};
		break;
	/* getresuid */
	case 165:
		switch (ndx) {
		case 0:
			p = "userland uid_t *";
			break;
		case 1:
			p = "userland uid_t *";
			break;
		case 2:
			p = "userland uid_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_poll */
	case 167:
		switch (ndx) {
		case 0:
			p = "userland struct pollfd *";
			break;
		case 1:
			p = "u_int";
			break;
		case 2:
			p = "int";
			break;
		default:
			break;
		};
		break;
	/* setresgid */
	case 169:
		switch (ndx) {
		case 0:
			p = "gid_t";
			break;
		case 1:
			p = "gid_t";
			break;
		case 2:
			p = "gid_t";
			break;
		default:
			break;
		};
		break;
	/* getresgid */
	case 170:
		switch (ndx) {
		case 0:
			p = "userland gid_t *";
			break;
		case 1:
			p = "userland gid_t *";
			break;
		case 2:
			p = "userland gid_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_prctl */
	case 171:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uintptr_t";
			break;
		case 3:
			p = "l_uintptr_t";
			break;
		case 4:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigreturn */
	case 172:
		break;
	/* linux_rt_sigaction */
	case 173:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_sigaction_t *";
			break;
		case 2:
			p = "userland l_sigaction_t *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigprocmask */
	case 174:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_sigset_t *";
			break;
		case 2:
			p = "userland l_sigset_t *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigpending */
	case 175:
		switch (ndx) {
		case 0:
			p = "userland l_sigset_t *";
			break;
		case 1:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigtimedwait */
	case 176:
		switch (ndx) {
		case 0:
			p = "userland l_sigset_t *";
			break;
		case 1:
			p = "userland l_siginfo_t *";
			break;
		case 2:
			p = "userland struct l_timespec *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigqueueinfo */
	case 177:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland l_siginfo_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_sigsuspend */
	case 178:
		switch (ndx) {
		case 0:
			p = "userland l_sigset_t *";
			break;
		case 1:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_pread */
	case 179:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_loff_t";
			break;
		default:
			break;
		};
		break;
	/* linux_pwrite */
	case 180:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_loff_t";
			break;
		default:
			break;
		};
		break;
	/* linux_chown */
	case 181:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_uid_t";
			break;
		case 2:
			p = "l_gid_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getcwd */
	case 182:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_capget */
	case 183:
		switch (ndx) {
		case 0:
			p = "userland struct l_user_cap_header *";
			break;
		case 1:
			p = "userland struct l_user_cap_data *";
			break;
		default:
			break;
		};
		break;
	/* linux_capset */
	case 184:
		switch (ndx) {
		case 0:
			p = "userland struct l_user_cap_header *";
			break;
		case 1:
			p = "userland struct l_user_cap_data *";
			break;
		default:
			break;
		};
		break;
	/* linux_sigaltstack */
	case 185:
		switch (ndx) {
		case 0:
			p = "userland l_stack_t *";
			break;
		case 1:
			p = "userland l_stack_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_sendfile */
	case 186:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland l_off_t *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_vfork */
	case 189:
		break;
	/* linux_mmap2 */
	case 192:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_ulong";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_getdents64 */
	case 202:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_pivot_root */
	case 203:
		break;
	/* linux_madvise */
	case 205:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_mincore */
	case 206:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "userland u_char *";
			break;
		default:
			break;
		};
		break;
	/* linux_gettid */
	case 207:
		break;
	/* linux_tkill */
	case 208:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_setxattr */
	case 209:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_lsetxattr */
	case 210:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_fsetxattr */
	case 211:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_getxattr */
	case 212:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_lgetxattr */
	case 213:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_fgetxattr */
	case 214:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_listxattr */
	case 215:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_llistxattr */
	case 216:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_flistxattr */
	case 217:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_removexattr */
	case 218:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_lremovexattr */
	case 219:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_fremovexattr */
	case 220:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_sys_futex */
	case 221:
		switch (ndx) {
		case 0:
			p = "userland uint32_t *";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "uint32_t";
			break;
		case 3:
			p = "userland struct l_timespec *";
			break;
		case 4:
			p = "userland uint32_t *";
			break;
		case 5:
			p = "uint32_t";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_setaffinity */
	case 222:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "userland l_ulong *";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_getaffinity */
	case 223:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "userland l_ulong *";
			break;
		default:
			break;
		};
		break;
	/* linux_set_tid_address */
	case 232:
		switch (ndx) {
		case 0:
			p = "userland l_int *";
			break;
		default:
			break;
		};
		break;
	/* linux_fadvise64 */
	case 233:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_loff_t";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_exit_group */
	case 234:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_lookup_dcookie */
	case 235:
		break;
	/* linux_epoll_create */
	case 236:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_epoll_ctl */
	case 237:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland struct epoll_event *";
			break;
		default:
			break;
		};
		break;
	/* linux_epoll_wait */
	case 238:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct epoll_event *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_remap_file_pages */
	case 239:
		break;
	/* linux_timer_create */
	case 240:
		switch (ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct sigevent *";
			break;
		case 2:
			p = "userland l_timer_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_timer_settime */
	case 241:
		switch (ndx) {
		case 0:
			p = "l_timer_t";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland const struct itimerspec *";
			break;
		case 3:
			p = "userland struct itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* linux_timer_gettime */
	case 242:
		switch (ndx) {
		case 0:
			p = "l_timer_t";
			break;
		case 1:
			p = "userland struct itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* linux_timer_getoverrun */
	case 243:
		switch (ndx) {
		case 0:
			p = "l_timer_t";
			break;
		default:
			break;
		};
		break;
	/* linux_timer_delete */
	case 244:
		switch (ndx) {
		case 0:
			p = "l_timer_t";
			break;
		default:
			break;
		};
		break;
	/* linux_clock_settime */
	case 245:
		switch (ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_clock_gettime */
	case 246:
		switch (ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_clock_getres */
	case 247:
		switch (ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_clock_nanosleep */
	case 248:
		switch (ndx) {
		case 0:
			p = "clockid_t";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland struct l_timespec *";
			break;
		case 3:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_tgkill */
	case 250:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_pid_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_utimes */
	case 251:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "userland struct l_timeval *";
			break;
		default:
			break;
		};
		break;
	/* linux_migrate_pages */
	case 258:
		break;
	/* linux_mbind */
	case 259:
		break;
	/* linux_get_mempolicy */
	case 260:
		break;
	/* linux_set_mempolicy */
	case 261:
		break;
	/* linux_mq_open */
	case 262:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_mode_t";
			break;
		case 3:
			p = "userland struct mq_attr *";
			break;
		default:
			break;
		};
		break;
	/* linux_mq_unlink */
	case 263:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_mq_timedsend */
	case 264:
		switch (ndx) {
		case 0:
			p = "l_mqd_t";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_uint";
			break;
		case 4:
			p = "userland const struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_mq_timedreceive */
	case 265:
		switch (ndx) {
		case 0:
			p = "l_mqd_t";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "userland l_uint *";
			break;
		case 4:
			p = "userland const struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_mq_notify */
	case 266:
		switch (ndx) {
		case 0:
			p = "l_mqd_t";
			break;
		case 1:
			p = "userland const struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_mq_getsetattr */
	case 267:
		switch (ndx) {
		case 0:
			p = "l_mqd_t";
			break;
		case 1:
			p = "userland const struct mq_attr *";
			break;
		case 2:
			p = "userland struct mq_attr *";
			break;
		default:
			break;
		};
		break;
	/* linux_kexec_load */
	case 268:
		break;
	/* linux_add_key */
	case 269:
		break;
	/* linux_request_key */
	case 270:
		break;
	/* linux_keyctl */
	case 271:
		break;
	/* linux_waitid */
	case 272:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_pid_t";
			break;
		case 2:
			p = "userland l_siginfo_t *";
			break;
		case 3:
			p = "l_int";
			break;
		case 4:
			p = "userland struct rusage *";
			break;
		default:
			break;
		};
		break;
	/* linux_ioprio_set */
	case 273:
		break;
	/* linux_ioprio_get */
	case 274:
		break;
	/* linux_inotify_add_watch */
	case 276:
		break;
	/* linux_inotify_rm_watch */
	case 277:
		break;
	/* linux_pselect6 */
	case 280:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_fd_set *";
			break;
		case 2:
			p = "userland l_fd_set *";
			break;
		case 3:
			p = "userland l_fd_set *";
			break;
		case 4:
			p = "userland struct l_timespec *";
			break;
		case 5:
			p = "userland l_uintptr_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_ppoll */
	case 281:
		switch (ndx) {
		case 0:
			p = "userland struct pollfd *";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "userland struct l_timespec *";
			break;
		case 3:
			p = "userland l_sigset_t *";
			break;
		case 4:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_unshare */
	case 282:
		break;
	/* linux_splice */
	case 283:
		switch (ndx) {
		case 0:
			p = "int";
			break;
		case 1:
			p = "userland l_loff_t *";
			break;
		case 2:
			p = "int";
			break;
		case 3:
			p = "userland l_loff_t *";
			break;
		case 4:
			p = "l_size_t";
			break;
		case 5:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_tee */
	case 284:
		break;
	/* linux_vmsplice */
	case 285:
		break;
	/* linux_openat */
	case 286:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_mkdirat */
	case 287:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_mknodat */
	case 288:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_mode_t";
			break;
		case 3:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_fchownat */
	case 289:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_uid_t";
			break;
		case 3:
			p = "l_gid_t";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_futimesat */
	case 290:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "userland struct l_timeval *";
			break;
		default:
			break;
		};
		break;
	/* linux_newfstatat */
	case 291:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "userland struct l_stat64 *";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_unlinkat */
	case 292:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_renameat */
	case 293:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_linkat */
	case 294:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland const char *";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_symlinkat */
	case 295:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_readlinkat */
	case 296:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland char *";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_fchmodat */
	case 297:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_mode_t";
			break;
		default:
			break;
		};
		break;
	/* linux_faccessat */
	case 298:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_get_robust_list */
	case 299:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct linux_robust_list_head **";
			break;
		case 2:
			p = "userland l_size_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_set_robust_list */
	case 300:
		switch (ndx) {
		case 0:
			p = "userland struct linux_robust_list_head *";
			break;
		case 1:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_move_pages */
	case 301:
		break;
	/* linux_getcpu */
	case 302:
		switch (ndx) {
		case 0:
			p = "userland l_uint *";
			break;
		case 1:
			p = "userland l_uint *";
			break;
		case 2:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* linux_epoll_pwait */
	case 303:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct epoll_event *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_int";
			break;
		case 4:
			p = "userland l_sigset_t *";
			break;
		case 5:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_utimensat */
	case 304:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const struct l_timespec *";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_timerfd_create */
	case 306:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_eventfd */
	case 307:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_sync_file_range */
	case 308:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_loff_t";
			break;
		case 2:
			p = "l_loff_t";
			break;
		case 3:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_fallocate */
	case 309:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_loff_t";
			break;
		case 3:
			p = "l_loff_t";
			break;
		default:
			break;
		};
		break;
	/* linux_timerfd_settime */
	case 311:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland const struct l_itimerspec *";
			break;
		case 3:
			p = "userland struct l_itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* linux_timerfd_gettime */
	case 312:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_itimerspec *";
			break;
		default:
			break;
		};
		break;
	/* linux_signalfd4 */
	case 313:
		break;
	/* linux_eventfd2 */
	case 314:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_epoll_create1 */
	case 315:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_dup3 */
	case 316:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_pipe2 */
	case 317:
		switch (ndx) {
		case 0:
			p = "userland l_int *";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_inotify_init1 */
	case 318:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_perf_event_open */
	case 319:
		break;
	/* linux_preadv */
	case 320:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "userland struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_pwritev */
	case 321:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "userland struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_rt_tgsigqueueinfo */
	case 322:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_pid_t";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland l_siginfo_t *";
			break;
		default:
			break;
		};
		break;
	/* linux_fanotify_init */
	case 323:
		break;
	/* linux_fanotify_mark */
	case 324:
		break;
	/* linux_prlimit64 */
	case 325:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "userland struct rlimit *";
			break;
		case 3:
			p = "userland struct rlimit *";
			break;
		default:
			break;
		};
		break;
	/* linux_socket */
	case 326:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_bind */
	case 327:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_connect */
	case 328:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_listen */
	case 329:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_accept */
	case 330:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getsockname */
	case 331:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_getpeername */
	case 332:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_socketpair */
	case 333:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_sendto */
	case 335:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_uint";
			break;
		case 4:
			p = "l_uintptr_t";
			break;
		case 5:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_recvfrom */
	case 337:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_uint";
			break;
		case 4:
			p = "l_uintptr_t";
			break;
		case 5:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_shutdown */
	case 338:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_setsockopt */
	case 339:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_uintptr_t";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_getsockopt */
	case 340:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_uintptr_t";
			break;
		case 4:
			p = "l_uintptr_t";
			break;
		default:
			break;
		};
		break;
	/* linux_sendmsg */
	case 341:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_recvmsg */
	case 342:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_recvmmsg */
	case 343:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_mmsghdr *";
			break;
		case 2:
			p = "l_uint";
			break;
		case 3:
			p = "l_uint";
			break;
		case 4:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_accept4 */
	case 344:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_uintptr_t";
			break;
		case 2:
			p = "l_uintptr_t";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_name_to_handle_at */
	case 345:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland struct l_file_handle *";
			break;
		case 3:
			p = "userland l_int *";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_open_by_handle_at */
	case 346:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_file_handle *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_clock_adjtime */
	case 347:
		break;
	/* linux_syncfs */
	case 348:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_sendmmsg */
	case 349:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_mmsghdr *";
			break;
		case 2:
			p = "l_uint";
			break;
		case 3:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_setns */
	case 350:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_process_vm_readv */
	case 351:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland const struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "userland const struct iovec *";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_process_vm_writev */
	case 352:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland const struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "userland const struct iovec *";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_finit_module */
	case 353:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_kcmp */
	case 354:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "l_pid_t";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_setattr */
	case 355:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_sched_getattr */
	case 356:
		switch (ndx) {
		case 0:
			p = "l_pid_t";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "l_uint";
			break;
		case 3:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_renameat2 */
	case 357:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland const char *";
			break;
		case 4:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_seccomp */
	case 358:
		switch (ndx) {
		case 0:
			p = "l_uint";
			break;
		case 1:
			p = "l_uint";
			break;
		case 2:
			p = "userland const char *";
			break;
		default:
			break;
		};
		break;
	/* linux_getrandom */
	case 359:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_memfd_create */
	case 360:
		switch (ndx) {
		case 0:
			p = "userland const char *";
			break;
		case 1:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_bpf */
	case 361:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland void *";
			break;
		case 2:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_execveat */
	case 362:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "userland const char **";
			break;
		case 3:
			p = "userland const char **";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_userfaultfd */
	case 364:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_membarrier */
	case 365:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_mlock2 */
	case 378:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_copy_file_range */
	case 379:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland l_loff_t *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland l_loff_t *";
			break;
		case 4:
			p = "l_size_t";
			break;
		case 5:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_preadv2 */
	case 380:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "userland const struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_pwritev2 */
	case 381:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "userland const struct iovec *";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_ulong";
			break;
		case 4:
			p = "l_ulong";
			break;
		case 5:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_statx */
	case 383:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_uint";
			break;
		case 3:
			p = "l_uint";
			break;
		case 4:
			p = "userland void *";
			break;
		default:
			break;
		};
		break;
	/* linux_pkey_alloc */
	case 384:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_ulong";
			break;
		default:
			break;
		};
		break;
	/* linux_pkey_free */
	case 385:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_pkey_mprotect */
	case 386:
		switch (ndx) {
		case 0:
			p = "l_ulong";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_ulong";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_rseq */
	case 387:
		switch (ndx) {
		case 0:
			p = "userland struct linux_rseq *";
			break;
		case 1:
			p = "uint32_t";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "uint32_t";
			break;
		default:
			break;
		};
		break;
	/* linux_io_pgetevents */
	case 388:
		break;
	/* linux_semtimedop */
	case 392:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct sembuf *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "userland struct l_timespec *";
			break;
		default:
			break;
		};
		break;
	/* linux_semget */
	case 393:
		switch (ndx) {
		case 0:
			p = "l_key_t";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_semctl */
	case 394:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "union l_semun";
			break;
		default:
			break;
		};
		break;
	/* linux_shmget */
	case 395:
		switch (ndx) {
		case 0:
			p = "l_key_t";
			break;
		case 1:
			p = "l_size_t";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_shmctl */
	case 396:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland struct l_shmid_ds *";
			break;
		default:
			break;
		};
		break;
	/* linux_shmat */
	case 397:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland char *";
			break;
		case 2:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_shmdt */
	case 398:
		switch (ndx) {
		case 0:
			p = "userland char *";
			break;
		default:
			break;
		};
		break;
	/* linux_msgget */
	case 399:
		switch (ndx) {
		case 0:
			p = "l_key_t";
			break;
		case 1:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_msgsnd */
	case 400:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_msgbuf *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_msgrcv */
	case 401:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct l_msgbuf *";
			break;
		case 2:
			p = "l_size_t";
			break;
		case 3:
			p = "l_long";
			break;
		case 4:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_msgctl */
	case 402:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland struct l_msqid_ds *";
			break;
		default:
			break;
		};
		break;
	/* linux_pidfd_send_signal */
	case 424:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "l_int";
			break;
		case 2:
			p = "userland l_siginfo_t *";
			break;
		case 3:
			p = "l_uint";
			break;
		default:
			break;
		};
		break;
	/* linux_io_uring_setup */
	case 425:
		break;
	/* linux_io_uring_enter */
	case 426:
		break;
	/* linux_io_uring_register */
	case 427:
		break;
	/* linux_open_tree */
	case 428:
		break;
	/* linux_move_mount */
	case 429:
		break;
	/* linux_fsopen */
	case 430:
		break;
	/* linux_fsconfig */
	case 431:
		break;
	/* linux_fsmount */
	case 432:
		break;
	/* linux_fspick */
	case 433:
		break;
	/* linux_pidfd_open */
	case 434:
		break;
	/* linux_clone3 */
	case 435:
		switch (ndx) {
		case 0:
			p = "userland struct l_user_clone_args *";
			break;
		case 1:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_close_range */
	case 436:
		break;
	/* linux_openat2 */
	case 437:
		break;
	/* linux_pidfd_getfd */
	case 438:
		break;
	/* linux_faccessat2 */
	case 439:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland const char *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "l_int";
			break;
		default:
			break;
		};
		break;
	/* linux_process_madvise */
	case 440:
		break;
	/* linux_epoll_pwait2 */
	case 441:
		switch (ndx) {
		case 0:
			p = "l_int";
			break;
		case 1:
			p = "userland struct epoll_event *";
			break;
		case 2:
			p = "l_int";
			break;
		case 3:
			p = "userland struct l_timespec *";
			break;
		case 4:
			p = "userland l_sigset_t *";
			break;
		case 5:
			p = "l_size_t";
			break;
		default:
			break;
		};
		break;
	/* linux_mount_setattr */
	case 442:
		break;
	default:
		break;
	};
	if (p != NULL)
		strlcpy(desc, p, descsz);
}
static void
systrace_return_setargdesc(int sysnum, int ndx, char *desc, size_t descsz)
{
	const char *p = NULL;
	switch (sysnum) {
#define	nosys	linux_nosys
	/* linux_exit */
	case 1:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fork */
	case 2:
	/* read */
	case 3:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* write */
	case 4:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_open */
	case 5:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* close */
	case 6:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_creat */
	case 8:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_link */
	case 9:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_unlink */
	case 10:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_execve */
	case 11:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_chdir */
	case 12:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_time */
	case 13:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mknod */
	case 14:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_chmod */
	case 15:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lchown */
	case 16:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lseek */
	case 19:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getpid */
	case 20:
	/* linux_mount */
	case 21:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_umount */
	case 22:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setuid */
	case 23:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getuid */
	case 24:
	/* linux_ptrace */
	case 26:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_alarm */
	case 27:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pause */
	case 29:
	/* linux_utime */
	case 30:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_access */
	case 33:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sync */
	case 36:
	/* linux_kill */
	case 37:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rename */
	case 38:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mkdir */
	case 39:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rmdir */
	case 40:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* dup */
	case 41:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pipe */
	case 42:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_times */
	case 43:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_brk */
	case 45:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setgid */
	case 46:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getgid */
	case 47:
	/* geteuid */
	case 49:
	/* getegid */
	case 50:
	/* acct */
	case 51:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ioctl */
	case 54:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fcntl */
	case 55:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setpgid */
	case 57:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* umask */
	case 60:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* chroot */
	case 61:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ustat */
	case 62:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* dup2 */
	case 63:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getppid */
	case 64:
	/* getpgrp */
	case 65:
	/* setsid */
	case 66:
	/* setreuid */
	case 70:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setregid */
	case 71:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sethostname */
	case 74:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setrlimit */
	case 75:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getrlimit */
	case 76:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getrusage */
	case 77:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* gettimeofday */
	case 78:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* settimeofday */
	case 79:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getgroups */
	case 80:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setgroups */
	case 81:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_select */
	case 82:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_symlink */
	case 83:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_readlink */
	case 85:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* swapon */
	case 87:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_reboot */
	case 88:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mmap */
	case 90:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* munmap */
	case 91:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_truncate */
	case 92:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ftruncate */
	case 93:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchmod */
	case 94:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchown */
	case 95:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getpriority */
	case 96:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setpriority */
	case 97:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_statfs */
	case 99:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fstatfs */
	case 100:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ioperm */
	case 101:
	/* linux_syslog */
	case 103:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setitimer */
	case 104:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getitimer */
	case 105:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_newstat */
	case 106:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_newlstat */
	case 107:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_newfstat */
	case 108:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_iopl */
	case 110:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_vhangup */
	case 111:
	/* linux_wait4 */
	case 114:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_swapoff */
	case 115:
	/* linux_sysinfo */
	case 116:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fsync */
	case 118:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clone */
	case 120:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setdomainname */
	case 121:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_newuname */
	case 122:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_modify_ldt */
	case 123:
	/* linux_adjtimex */
	case 124:
	/* linux_mprotect */
	case 125:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_init_module */
	case 128:
	/* linux_delete_module */
	case 129:
	/* linux_quotactl */
	case 131:
	/* getpgid */
	case 132:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* fchdir */
	case 133:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_personality */
	case 136:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setfsuid */
	case 138:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setfsgid */
	case 139:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getdents */
	case 141:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* flock */
	case 143:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_msync */
	case 144:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* readv */
	case 145:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* writev */
	case 146:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getsid */
	case 147:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fdatasync */
	case 148:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sysctl */
	case 149:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* mlock */
	case 150:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* munlock */
	case 151:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* mlockall */
	case 152:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* munlockall */
	case 153:
	/* linux_sched_setparam */
	case 154:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_getparam */
	case 155:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_setscheduler */
	case 156:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_getscheduler */
	case 157:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* sched_yield */
	case 158:
	/* linux_sched_get_priority_max */
	case 159:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_get_priority_min */
	case 160:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_rr_get_interval */
	case 161:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_nanosleep */
	case 162:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mremap */
	case 163:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setresuid */
	case 164:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getresuid */
	case 165:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_poll */
	case 167:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* setresgid */
	case 169:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* getresgid */
	case 170:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_prctl */
	case 171:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigreturn */
	case 172:
	/* linux_rt_sigaction */
	case 173:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigprocmask */
	case 174:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigpending */
	case 175:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigtimedwait */
	case 176:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigqueueinfo */
	case 177:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_sigsuspend */
	case 178:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pread */
	case 179:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pwrite */
	case 180:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_chown */
	case 181:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getcwd */
	case 182:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_capget */
	case 183:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_capset */
	case 184:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sigaltstack */
	case 185:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sendfile */
	case 186:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_vfork */
	case 189:
	/* linux_mmap2 */
	case 192:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getdents64 */
	case 202:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pivot_root */
	case 203:
	/* linux_madvise */
	case 205:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mincore */
	case 206:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_gettid */
	case 207:
	/* linux_tkill */
	case 208:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setxattr */
	case 209:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lsetxattr */
	case 210:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fsetxattr */
	case 211:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getxattr */
	case 212:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lgetxattr */
	case 213:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fgetxattr */
	case 214:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_listxattr */
	case 215:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_llistxattr */
	case 216:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_flistxattr */
	case 217:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_removexattr */
	case 218:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lremovexattr */
	case 219:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fremovexattr */
	case 220:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sys_futex */
	case 221:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_setaffinity */
	case 222:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_getaffinity */
	case 223:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_set_tid_address */
	case 232:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fadvise64 */
	case 233:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_exit_group */
	case 234:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_lookup_dcookie */
	case 235:
	/* linux_epoll_create */
	case 236:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_epoll_ctl */
	case 237:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_epoll_wait */
	case 238:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_remap_file_pages */
	case 239:
	/* linux_timer_create */
	case 240:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timer_settime */
	case 241:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timer_gettime */
	case 242:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timer_getoverrun */
	case 243:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timer_delete */
	case 244:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clock_settime */
	case 245:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clock_gettime */
	case 246:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clock_getres */
	case 247:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clock_nanosleep */
	case 248:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_tgkill */
	case 250:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_utimes */
	case 251:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_migrate_pages */
	case 258:
	/* linux_mbind */
	case 259:
	/* linux_get_mempolicy */
	case 260:
	/* linux_set_mempolicy */
	case 261:
	/* linux_mq_open */
	case 262:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mq_unlink */
	case 263:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mq_timedsend */
	case 264:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mq_timedreceive */
	case 265:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mq_notify */
	case 266:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mq_getsetattr */
	case 267:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_kexec_load */
	case 268:
	/* linux_add_key */
	case 269:
	/* linux_request_key */
	case 270:
	/* linux_keyctl */
	case 271:
	/* linux_waitid */
	case 272:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ioprio_set */
	case 273:
	/* linux_ioprio_get */
	case 274:
	/* linux_inotify_add_watch */
	case 276:
	/* linux_inotify_rm_watch */
	case 277:
	/* linux_pselect6 */
	case 280:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_ppoll */
	case 281:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_unshare */
	case 282:
	/* linux_splice */
	case 283:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_tee */
	case 284:
	/* linux_vmsplice */
	case 285:
	/* linux_openat */
	case 286:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mkdirat */
	case 287:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mknodat */
	case 288:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fchownat */
	case 289:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_futimesat */
	case 290:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_newfstatat */
	case 291:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_unlinkat */
	case 292:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_renameat */
	case 293:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_linkat */
	case 294:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_symlinkat */
	case 295:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_readlinkat */
	case 296:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fchmodat */
	case 297:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_faccessat */
	case 298:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_get_robust_list */
	case 299:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_set_robust_list */
	case 300:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_move_pages */
	case 301:
	/* linux_getcpu */
	case 302:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_epoll_pwait */
	case 303:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_utimensat */
	case 304:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timerfd_create */
	case 306:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_eventfd */
	case 307:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sync_file_range */
	case 308:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fallocate */
	case 309:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timerfd_settime */
	case 311:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_timerfd_gettime */
	case 312:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_signalfd4 */
	case 313:
	/* linux_eventfd2 */
	case 314:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_epoll_create1 */
	case 315:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_dup3 */
	case 316:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pipe2 */
	case 317:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_inotify_init1 */
	case 318:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_perf_event_open */
	case 319:
	/* linux_preadv */
	case 320:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pwritev */
	case 321:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rt_tgsigqueueinfo */
	case 322:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_fanotify_init */
	case 323:
	/* linux_fanotify_mark */
	case 324:
	/* linux_prlimit64 */
	case 325:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_socket */
	case 326:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_bind */
	case 327:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_connect */
	case 328:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_listen */
	case 329:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_accept */
	case 330:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getsockname */
	case 331:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getpeername */
	case 332:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_socketpair */
	case 333:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sendto */
	case 335:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_recvfrom */
	case 337:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_shutdown */
	case 338:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setsockopt */
	case 339:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getsockopt */
	case 340:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sendmsg */
	case 341:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_recvmsg */
	case 342:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_recvmmsg */
	case 343:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_accept4 */
	case 344:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_name_to_handle_at */
	case 345:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_open_by_handle_at */
	case 346:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_clock_adjtime */
	case 347:
	/* linux_syncfs */
	case 348:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sendmmsg */
	case 349:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_setns */
	case 350:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_process_vm_readv */
	case 351:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_process_vm_writev */
	case 352:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_finit_module */
	case 353:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_kcmp */
	case 354:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_setattr */
	case 355:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_sched_getattr */
	case 356:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_renameat2 */
	case 357:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_seccomp */
	case 358:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_getrandom */
	case 359:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_memfd_create */
	case 360:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_bpf */
	case 361:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_execveat */
	case 362:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_userfaultfd */
	case 364:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_membarrier */
	case 365:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mlock2 */
	case 378:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_copy_file_range */
	case 379:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_preadv2 */
	case 380:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pwritev2 */
	case 381:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_statx */
	case 383:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pkey_alloc */
	case 384:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pkey_free */
	case 385:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pkey_mprotect */
	case 386:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_rseq */
	case 387:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_io_pgetevents */
	case 388:
	/* linux_semtimedop */
	case 392:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_semget */
	case 393:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_semctl */
	case 394:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_shmget */
	case 395:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_shmctl */
	case 396:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_shmat */
	case 397:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_shmdt */
	case 398:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_msgget */
	case 399:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_msgsnd */
	case 400:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_msgrcv */
	case 401:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_msgctl */
	case 402:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_pidfd_send_signal */
	case 424:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_io_uring_setup */
	case 425:
	/* linux_io_uring_enter */
	case 426:
	/* linux_io_uring_register */
	case 427:
	/* linux_open_tree */
	case 428:
	/* linux_move_mount */
	case 429:
	/* linux_fsopen */
	case 430:
	/* linux_fsconfig */
	case 431:
	/* linux_fsmount */
	case 432:
	/* linux_fspick */
	case 433:
	/* linux_pidfd_open */
	case 434:
	/* linux_clone3 */
	case 435:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_close_range */
	case 436:
	/* linux_openat2 */
	case 437:
	/* linux_pidfd_getfd */
	case 438:
	/* linux_faccessat2 */
	case 439:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_process_madvise */
	case 440:
	/* linux_epoll_pwait2 */
	case 441:
		if (ndx == 0 || ndx == 1)
			p = "int";
		break;
	/* linux_mount_setattr */
	case 442:
	default:
		break;
	};
	if (p != NULL)
		strlcpy(desc, p, descsz);
}
