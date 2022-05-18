#include <cpu.h>
#include <string.h>
#include <debug.h>

struct syscall_handle {
	void (*handler)(struct registers*);
	void (*logger)();

	const char *name;
};

static struct syscall_handle syscall_list[] = {
	{ .handler = NULL, .logger = NULL, .name = "open" },
	{ .handler = NULL, .logger = NULL, .name = "close" },
	{ .handler = NULL, .logger = NULL, .name = "read" },
	{ .handler = NULL, .logger = NULL, .name = "write" },
	{ .handler = NULL, .logger = NULL, .name = "seek" },
	{ .handler = NULL, .logger = NULL, .name = "dup" },
	{ .handler = NULL, .logger = NULL, .name = "dup2" },
	{ .handler = NULL, .logger = NULL, .name = "mmap" },
	{ .handler = NULL, .logger = NULL, .name = "munamp" },
	{ .handler = NULL, .logger = NULL, .name = "set_fs_base" },
	{ .handler = NULL, .logger = NULL, .name = "get_fs_base" },
	{ .handler = NULL, .logger = NULL, .name = "set_gs_base" },
	{ .handler = NULL, .logger = NULL, .name = "get_gs_base" },
	{ .handler = NULL, .logger = NULL, .name = "syslog" },
	{ .handler = NULL, .logger = NULL, .name = "exit" },
	{ .handler = NULL, .logger = NULL, .name = "getpid" },
	{ .handler = NULL, .logger = NULL, .name = "gettid" },
	{ .handler = NULL, .logger = NULL, .name = "getppid" },
	{ .handler = NULL, .logger = NULL, .name = "isatty" },
	{ .handler = NULL, .logger = NULL, .name = "fcntl" },
	{ .handler = NULL, .logger = NULL, .name = "fstat" },
	{ .handler = NULL, .logger = NULL, .name = "fstatat" },
	{ .handler = NULL, .logger = NULL, .name = "ioctl" },
	{ .handler = NULL, .logger = NULL, .name = "fork" },
	{ .handler = NULL, .logger = NULL, .name = "waitpid" },
	{ .handler = NULL, .logger = NULL, .name = "readdir" },
	{ .handler = NULL, .logger = NULL, .name = "execve" },
};

extern void syscall_handler(struct registers *regs) {
	uint64_t syscall_number = regs->rax;

	if(syscall_number >= LENGTHOF(syscall_list)) {
		print("SYSCALL: unknown syscall number %d\n", syscall_number);
		return;
	}

	static char message_lock = 0;

	spinlock(&message_lock);
	syscall_list[syscall_number].logger();
	spinrelease(&message_lock);

	syscall_list[syscall_number].handler(regs);

	if(regs->rax != -1) {
		set_errno(0);
	}

	print("SYSCALL: %s returning %x with errno %d\n", syscall_list[syscall_number].name, regs->rax, get_errno());
}
