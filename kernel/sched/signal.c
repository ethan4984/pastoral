#include <sched/signal.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
	struct sched_task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	if((sig < 1 && sig > 32) || (sig == SIGKILL || sig == SIGSTOP)) {
		set_errno(EINVAL);
		return -1;
	}

	spinlock(&task->sig_lock);

	struct sigaction *current_action = &task->sigactions[sig - 1];

	if(old) {
		*old = *current_action;
	}

	if(act) {
		*current_action = *act;
		current_action->sa_mask &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP));
	}

	spinrelease(&task->sig_lock);

	return 0;
}

int sigpending(sigset_t *set) {
	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic(""); 
	}

	*set = thread->signal_queue.sigpending;

	return 0;
}

void syscall_sigaction(struct registers *regs) {
	int sig = regs->rdi;
	const struct sigaction *act = (void*)regs->rsi;
	struct sigaction *old = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] sigaction: signum {%x}, act {%x}, old {%x}\n", CORE_LOCAL->pid, sig, act, old);
#endif

	regs->rax = sigaction(sig, act, old);
}

void syscall_sigpending(struct registers *regs) {
	sigset_t *set = (void*)regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] sigaction: {%x}\n", CORE_LOCAL->pid, set);
#endif

	regs->rax = sigpending(set);
}
