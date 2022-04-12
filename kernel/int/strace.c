#include <cpu.h>
#include <string.h>
#include <debug.h>

struct syscall_handle {
	void (*handler)(struct registers*);
	void (*logger)();

	const char *name;
};

static struct syscall_handle syscall_list[] = {

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
