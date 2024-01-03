#include <cpu.h>
#include <string.h>
#include <debug.h>
#include <sched/sched.h>
#include <lib/errno.h>

#define SYSCALL_FD 1
#define SYSCALL_SOCKET 2
#define SYSCALL_SCHED 3
#define SYSCALL_SIGNAL 4
#define SYSCALL_MEM 5
#define SYSCALL_TIME 6

struct syscall_handle {
	void (*handler)(struct registers*);
	const char *name;
	int class;
};

extern void syscall_openat(struct registers*);
extern void syscall_unlinkat(struct registers*);
extern void syscall_close(struct registers*);
extern void syscall_read(struct registers*);
extern void syscall_write(struct registers*);
extern void syscall_seek(struct registers*);
extern void syscall_mmap(struct registers*);
extern void syscall_munmap(struct registers*);
extern void syscall_stat(struct registers*);
extern void syscall_statat(struct registers*);
extern void syscall_getpid(struct registers*);
extern void syscall_getppid(struct registers*);
extern void syscall_gettid(struct registers*);
extern void syscall_dup(struct registers*);
extern void syscall_dup2(struct registers*);
extern void syscall_fcntl(struct registers*);
extern void syscall_fork(struct registers*);
extern void syscall_exit(struct registers*);
extern void syscall_waitpid(struct registers*);
extern void syscall_execve(struct registers*);
extern void syscall_waitpid(struct registers*);
extern void syscall_readdir(struct registers*);
extern void syscall_chdir(struct registers*);
extern void syscall_getcwd(struct registers*);
extern void syscall_faccessat(struct registers*);
extern void syscall_pipe(struct registers*);
extern void syscall_ioctl(struct registers*);
extern void syscall_umask(struct registers*);
extern void syscall_getuid(struct registers*);
extern void syscall_geteuid(struct registers*);
extern void syscall_setuid(struct registers*);
extern void syscall_seteuid(struct registers*);
extern void syscall_getgid(struct registers*);
extern void syscall_getegid(struct registers*);
extern void syscall_setgid(struct registers*);
extern void syscall_setegid(struct registers*);
extern void syscall_fchmod(struct registers*);
extern void syscall_fchmodat(struct registers*);
extern void syscall_fchownat(struct registers*);
extern void syscall_sigaction(struct registers*);
extern void syscall_sigpending(struct registers*);
extern void syscall_sigprocmask(struct registers*);
extern void syscall_kill(struct registers*);
extern void syscall_setpgid(struct registers*);
extern void syscall_getpgid(struct registers*);
extern void syscall_setsid(struct registers*);
extern void syscall_getsid(struct registers*);
extern void syscall_pause(struct registers*);
extern void syscall_sigsuspend(struct registers*);
extern void syscall_poll(struct registers*);
extern void syscall_ppoll(struct registers*);
extern void syscall_socket(struct registers*);
extern void syscall_getsockname(struct registers*);
extern void syscall_getpeername(struct registers*);
extern void syscall_listen(struct registers*);
extern void syscall_accept(struct registers*);
extern void syscall_bind(struct registers*);
extern void syscall_connect(struct registers*);
extern void syscall_sigreturn(struct registers*);
extern void syscall_sendmsg(struct registers*);
extern void syscall_recvmsg(struct registers*);
extern void syscall_clone(struct registers*);
extern void syscall_futex(struct registers*);
extern void syscall_utimensat(struct registers*);
extern void syscall_renameat(struct registers*);
extern void syscall_symlinkat(struct registers*);
extern void syscall_readlinkat(struct registers*);
extern void syscall_mkdirat(struct registers*);
extern void syscall_usleep(struct registers*);
extern void syscall_clock_gettime(struct registers*);
extern void syscall_linkat(struct registers*);

static void syscall_set_fs_base(struct registers *regs) {
	uint64_t addr = regs->rdi;

	CURRENT_TASK->user_fs_base = addr;

#if defined(SYSCALL_DEBUG_SCHED)
	print("syscall: [pid %x, tid %x] set_fs_base: addr {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, addr);
#endif

	set_user_fs(addr);

	regs->rax = 0;
}

static void syscall_get_fs_base(struct registers *regs) {
#if defined(SYSCALL_DEBUG_SCHED)
	print("syscall: [pid %x, tid %x] get_fs_base\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif

	regs->rax = get_user_fs();
}

static void syscall_set_gs_base(struct registers *regs) {
	uint64_t addr = regs->rdi;

	CURRENT_TASK->user_gs_base = addr;

#if defined(SYSCALL_DEBUG_SCHED)
	print("syscall: [pid %x, tid %x] set_gs_base: addr {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, addr);
#endif

	set_user_gs(addr);

	regs->rax = 0;
}

static void syscall_get_gs_base(struct registers *regs) {
#if defined(SYSCALL_DEBUG_SCHED)
	print("syscall: [pid %x, tid %x] get_gs_base\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif

	regs->rax = get_user_gs();
}

static void syscall_syslog(struct registers *regs) {
	const char *str = (void*)regs->rdi;
	print("%s\n", str);
}

static struct syscall_handle syscall_list[] = {
	{ .handler = syscall_openat, .name = "open", .class = SYSCALL_FD }, // 0
	{ .handler = syscall_close, .name = "close", .class = SYSCALL_FD}, // 1
	{ .handler = syscall_read, .name = "read", .class = SYSCALL_FD }, // 2
	{ .handler = syscall_write, .name = "write", .class = SYSCALL_FD }, // 3
	{ .handler = syscall_seek, .name = "seek", .class = SYSCALL_FD }, // 4
	{ .handler = syscall_dup, .name = "dup", .class = SYSCALL_FD }, // 5
	{ .handler = syscall_dup2, .name = "dup2", .class = SYSCALL_FD }, // 6
	{ .handler = syscall_mmap, .name = "mmap", .class = SYSCALL_MEM }, // 7
	{ .handler = syscall_munmap, .name = "munamp", .class = SYSCALL_MEM }, // 8
	{ .handler = syscall_set_fs_base, .name = "set_fs_base" }, // 9
	{ .handler = syscall_set_gs_base, .name = "set_gs_base" }, // 10
	{ .handler = syscall_get_fs_base, .name = "get_fs_base" }, // 11
	{ .handler = syscall_get_gs_base, .name = "get_gs_base" }, // 12
	{ .handler = syscall_syslog, .name = "syslog" }, // 13
	{ .handler = syscall_exit, .name = "exit", .class = SYSCALL_SCHED }, // 14
	{ .handler = syscall_getpid, .name = "getpid", .class = SYSCALL_SCHED }, // 15
	{ .handler = syscall_gettid, .name = "gettid", .class = SYSCALL_SCHED }, // 16
	{ .handler = syscall_getppid, .name = "getppid", .class = SYSCALL_SCHED }, // 17
	{ .handler = NULL, .name = "isatty", .class = SYSCALL_FD }, // 18
	{ .handler = syscall_fcntl, .name = "fcntl", .class = SYSCALL_FD }, // 19
	{ .handler = syscall_stat, .name = "fstat", .class = SYSCALL_FD }, // 20
	{ .handler = syscall_statat, .name = "fstatat", .class = SYSCALL_FD }, // 21
	{ .handler = syscall_ioctl, .name = "ioctl" }, // 22
	{ .handler = syscall_fork, .name = "fork", .class = SYSCALL_SCHED }, // 23
	{ .handler = syscall_waitpid, .name = "waitpid", .class = SYSCALL_SCHED }, // 24
	{ .handler = syscall_readdir, .name = "readdir", .class = SYSCALL_FD }, // 25
	{ .handler = syscall_execve, .name = "execve", .class = SYSCALL_SCHED }, // 26
	{ .handler = syscall_getcwd, .name = "getcwd", .class = SYSCALL_FD }, // 27
	{ .handler = syscall_chdir, .name = "chdir", .class = SYSCALL_FD }, // 28
	{ .handler = syscall_faccessat, .name = "faccessat", .class = SYSCALL_FD }, // 29
	{ .handler = syscall_pipe, .name = "pipe", .class = SYSCALL_FD }, // 30
	{ .handler = syscall_umask, .name = "umask" }, // 31
	{ .handler = syscall_getuid, .name = "getuid", .class = SYSCALL_SCHED }, // 32
	{ .handler = syscall_geteuid, .name = "geteuid", .class = SYSCALL_SCHED }, // 33
	{ .handler = syscall_setuid, .name = "setuid", .class = SYSCALL_SCHED }, // 34
	{ .handler = syscall_seteuid, .name = "seteuid", .class = SYSCALL_SCHED }, // 35
	{ .handler = syscall_getgid, .name = "getgid", .class = SYSCALL_SCHED }, // 36
	{ .handler = syscall_getegid, .name = "getegid", .class = SYSCALL_SCHED }, // 37
	{ .handler = syscall_setgid, .name = "setgid", .class = SYSCALL_SCHED }, // 38
	{ .handler = syscall_setegid, .name = "setegid", .class = SYSCALL_SCHED }, // 39
	{ .handler = syscall_fchmod, .name = "fchmod", .class = SYSCALL_FD }, // 40
	{ .handler = syscall_fchmodat, .name = "fchmodat", .class = SYSCALL_FD }, // 41
	{ .handler = syscall_fchownat, .name = "fchownat", .class = SYSCALL_FD }, // 42
	{ .handler = syscall_sigaction, .name = "sigaction", .class = SYSCALL_SIGNAL }, // 43
	{ .handler = syscall_sigpending, .name = "sigpending", .class = SYSCALL_SIGNAL  }, // 44
	{ .handler = syscall_sigprocmask, .name = "sigprocmask", .class = SYSCALL_SIGNAL  }, // 45
	{ .handler = syscall_kill, .name = "kill", .class = SYSCALL_SCHED }, // 46
	{ .handler = syscall_setpgid, .name = "setpgid", .class = SYSCALL_SCHED }, // 47
	{ .handler = syscall_getpgid, .name = "getpgid", .class = SYSCALL_SCHED }, // 48
	{ .handler = syscall_setsid, .name = "setsid", .class = SYSCALL_SCHED }, // 49
	{ .handler = syscall_getsid, .name = "getsid", .class = SYSCALL_SCHED }, // 50
	{ .handler = syscall_pause, .name = "pause", .class = SYSCALL_SCHED }, // 51
	{ .handler = syscall_sigsuspend, .name = "sigsuspend", .class = SYSCALL_SIGNAL  }, // 52
	{ .handler = syscall_poll, .name = "poll", .class = SYSCALL_FD }, // 53
	{ .handler = syscall_ppoll, .name = "ppoll", .class = SYSCALL_FD }, // 54
	{ .handler = syscall_socket, .name = "socket", .class = SYSCALL_SOCKET  }, // 55
	{ .handler = syscall_getsockname, .name = "getsockname", .class = SYSCALL_SOCKET }, // 56
	{ .handler = syscall_getpeername, .name = "getpeername", .class = SYSCALL_SOCKET }, // 57
	{ .handler = syscall_listen, .name = "listen", .class = SYSCALL_SOCKET }, // 58
	{ .handler = syscall_accept, .name = "accept", .class = SYSCALL_SOCKET }, // 59
	{ .handler = syscall_bind, .name = "bind", .class = SYSCALL_SOCKET }, // 60
	{ .handler = syscall_connect, .name = "connect", .class = SYSCALL_SOCKET }, // 61
	{ .handler = syscall_sigreturn, .name = "sigreturn", .class = SYSCALL_SIGNAL }, // 62
	{ .handler = syscall_sendmsg, .name = "sendmsg", .class = SYSCALL_SOCKET }, // 63
	{ .handler = syscall_recvmsg, .name = "recvmsg", .class = SYSCALL_SOCKET }, // 64
	{ .handler = syscall_clone, .name = "clone", .class = SYSCALL_SCHED }, // 65
	{ .handler = syscall_futex, .name = "futex", .class = SYSCALL_SCHED }, // 66
	{ .handler = syscall_unlinkat, .name = "unlinkat", .class = SYSCALL_FD }, // 67
	{ .handler = syscall_utimensat, .name = "utimensat", .class = SYSCALL_FD }, // 68
	{ .handler = syscall_renameat, .name = "renameat", .class = SYSCALL_FD }, // 69
	{ .handler = syscall_symlinkat, .name = "symlinkat", .class = SYSCALL_FD }, // 70
	{ .handler = syscall_readlinkat, .name = "readlinkat", .class = SYSCALL_FD }, // 71
	{ .handler = syscall_mkdirat, .name = "mkdirat", .class = SYSCALL_FD }, // 72
	{ .handler = syscall_usleep, .name = "usleep", .class = SYSCALL_TIME}, // 73
	{ .handler = syscall_clock_gettime, .name = "clock_gettime", .class = SYSCALL_TIME }, // 74
	{ .handler = syscall_linkat, .name = "linkat", .class = SYSCALL_FD } // 75
};

extern void syscall_handler(struct registers *regs) {
	uint64_t syscall_number = regs->rax;

	if(syscall_number >= LENGTHOF(syscall_list)) {
		print("SYSCALL: unknown syscall number %d\n", syscall_number);
		regs->rax = -1;
		set_errno(ENOSYS);
		return;
	}

	CURRENT_TASK->signal_queue.active = false;

	if(syscall_list[syscall_number].handler != NULL) {
		syscall_list[syscall_number].handler(regs);
	} else {
		panic("null syscall %s", syscall_list[syscall_number].name);
	}

	if(regs->rax != -1) {
		set_errno(0);
	}

#ifndef SYSCALL_DEBUG_ALL
	switch(syscall_list[syscall_number].class) {
		case SYSCALL_FD:
#if defined(SYSCALL_DEBUG_FD)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
		case SYSCALL_SCHED:
#if defined(SYSCALL_DEBUG_SCHED)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
		case SYSCALL_SOCKET:
#if defined(SYSCALL_DEBUG_SOCKET)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
		case SYSCALL_SIGNAL:
#if defined(SYSCALL_DEBUG_SIGNAL)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
		case SYSCALL_MEM:
#if defined(SYSCALL_DEBUG_MEM)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
		case SYSCALL_TIME:
#if defined(SYSCALL_DEBUG_TIME)
			print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
					CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif
			break;
	}
#else
	print("syscall: [pid %x, tid %x] %s returning %x with errno %d\n", CORE_LOCAL->pid,
			CORE_LOCAL->tid, syscall_list[syscall_number].name, regs->rax, get_errno());
#endif


	CURRENT_TASK->signal_queue.active = true;
}
