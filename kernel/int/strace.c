#include <cpu.h>
#include <string.h>
#include <debug.h>
#include <sched/sched.h>

struct syscall_handle {
	void (*handler)(struct registers*);
	const char *name;
};

extern void syscall_open(struct registers*);
extern void syscall_close(struct registers*);
extern void syscall_read(struct registers*);
extern void syscall_write(struct registers*);
extern void syscall_seek(struct registers*);
extern void syscall_mmap(struct registers*);
extern void syscall_stat(struct registers*);
extern void syscall_statat(struct registers*);
extern void syscall_getpid(struct registers*);
extern void syscall_getppid(struct registers*);
extern void syscall_gettid(struct registers*);
extern void syscall_dup(struct registers*);
extern void syscall_dup2(struct registers*);
extern void syscall_fcntl(struct registers*);

static void syscall_set_fs_base(struct registers *regs) {
	uint64_t addr = regs->rdi;

	CURRENT_THREAD->user_fs_base = addr;

#ifndef SYSCALL_DEBUG
	print("syscall: set_fs_base: addr {%x}\n", addr);
#endif

	set_user_fs(addr);

	regs->rax = 0;
}

static void syscall_get_fs_base(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: get_fs_base\n");
#endif

	regs->rax = get_user_fs();
}

static void syscall_set_gs_base(struct registers *regs) {
	uint64_t addr = regs->rdi;

	CURRENT_THREAD->user_gs_base = addr;

#ifndef SYSCALL_DEBUG
	print("syscall: set_gs_base: addr {%x}\n", addr);
#endif

	set_user_gs(addr);

	regs->rax = 0;
}

static void syscall_get_gs_base(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: get_gs_base\n");
#endif

	regs->rax = get_user_gs();
}

static void syscall_syslog(struct registers *regs) {
	const char *str = (void*)regs->rdi;
	print("%s\n", str);
}

static struct syscall_handle syscall_list[] = {
	{ .handler = syscall_open, .name = "open" },
	{ .handler = syscall_close, .name = "close" },
	{ .handler = syscall_read, .name = "read" },
	{ .handler = syscall_write, .name = "write" },
	{ .handler = syscall_seek, .name = "seek" },
	{ .handler = syscall_dup, .name = "dup" },
	{ .handler = syscall_dup2, .name = "dup2" },
	{ .handler = syscall_mmap, .name = "mmap" },
	{ .handler = NULL, .name = "munamp" },
	{ .handler = syscall_set_fs_base, .name = "set_fs_base" },
	{ .handler = syscall_get_fs_base, .name = "get_fs_base" },
	{ .handler = syscall_set_gs_base, .name = "set_gs_base" },
	{ .handler = syscall_get_gs_base, .name = "get_gs_base" },
	{ .handler = syscall_syslog, .name = "syslog" },
	{ .handler = NULL, .name = "exit" },
	{ .handler = syscall_getpid, .name = "getpid" },
	{ .handler = syscall_gettid, .name = "gettid" },
	{ .handler = syscall_getppid, .name = "getppid" },
	{ .handler = NULL, .name = "isatty" },
	{ .handler = syscall_fcntl, .name = "fcntl" },
	{ .handler = syscall_stat, .name = "fstat" },
	{ .handler = syscall_statat, .name = "fstatat" },
	{ .handler = NULL, .name = "ioctl" },
	{ .handler = NULL, .name = "fork" },
	{ .handler = NULL, .name = "waitpid" },
	{ .handler = NULL, .name = "readdir" },
	{ .handler = NULL, .name = "execve" }
};

extern void syscall_handler(struct registers *regs) {
	uint64_t syscall_number = regs->rax;

	if(syscall_number >= LENGTHOF(syscall_list)) {
		print("SYSCALL: unknown syscall number %d\n", syscall_number);
		return;
	}

	if(syscall_list[syscall_number].handler != NULL) {
		syscall_list[syscall_number].handler(regs);
	} else {
		if(strcmp(syscall_list[syscall_number].name, "ioctl") == 0) {
			return;	
		}
		panic("null syscall %s", syscall_list[syscall_number].name);
	}

	if(regs->rax != -1) {
		set_errno(0);
	}

	print("SYSCALL: %s returning %x with errno %d\n", syscall_list[syscall_number].name, regs->rax, get_errno());
}
