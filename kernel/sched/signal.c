#include <sched/signal.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
	struct sched_task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	if(signal_is_valid(sig) == -1 || (sig == SIGKILL || sig == SIGSTOP)) {
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

	spinlock(&thread->sig_lock);
	*set = thread->signal_queue.sigpending;
	spinrelease(&thread->sig_lock);

	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic(""); 
	}

	spinlock(&thread->sig_lock);

	if(oldset) {
		*oldset = thread->sigmask;
	}

	if(set) {
		switch(how) {
			case SIG_BLOCK:
				thread->sigmask |= *set;
				break;
			case SIG_UNBLOCK:
				thread->sigmask &= ~(*set);
				break; 
			case SIG_SETMASK:
				thread->sigmask = *set;
				break;
			default:
				set_errno(EINVAL); 
				spinrelease(&thread->sig_lock);
				return -1;
		}
	}

	spinrelease(&thread->sig_lock);

	return 0;
}

int signal_check_permissions(struct sched_task *sender, struct sched_task *target) {
	if(sender->real_uid == 0 || sender->effective_uid == 0) {
		return 0;
	}

	if(sender->real_uid == target->real_uid || sender->real_uid == target->effective_uid) {
		return 0;
	}

	if(sender->effective_uid == target->real_uid || sender->effective_uid == target->effective_uid) {
		return 0;
	}

	return -1;
}

int signal_is_valid(int sig) {
	if(sig < 1 || sig > SIGNAL_MAX) {
		return -1;
	}

	return 0;
}

int signal_send(struct sched_thread *sender, struct sched_thread *target, int sig) {
	if(signal_is_valid(sig) == -1 && sig != 0) {
		set_errno(EINVAL);
		return -1;
	}

	struct sched_task *sender_task = sched_translate_pid(sender->pid);
	struct sched_task *target_task = sched_translate_pid(target->pid);

	spinlock(&target->sig_lock);

	if(signal_check_permissions(sender_task, target_task) == -1) {
		set_errno(EPERM);
		spinrelease(&target->sig_lock);
		return -1;
	}

	struct signal_queue *signal_queue = &target->signal_queue;
	struct signal *signal = &signal_queue->queue[sig - 1];

	signal->refcnt = 1;
	signal->siginfo = alloc(sizeof(struct siginfo));
	signal->sigaction = &target_task->sigactions[sig - 1];
	signal->trigger = alloc(sizeof(struct event_trigger));
	*signal->trigger = (struct event_trigger) { .event = &target->sigwait, .event_type = EVENT_SIGNAL };
	signal->queue = signal_queue; 

	signal_queue->sigpending |= SIGMASK(sig);

	spinrelease(&target->sig_lock);

	return 0;
}

int kill(pid_t pid, int sig) {
	if(signal_is_valid(sig) == -1) {
		set_errno(EINVAL);
		return -1;
	}

	struct sched_thread *sender = CURRENT_THREAD;
	if(sender == NULL) {
		panic("");
	}

	if(pid > 0) {
		struct sched_thread *target = sched_translate_tid(pid, 0);
		if(target == NULL) {
			set_errno(ESRCH);
			return -1;
		}

		signal_send(sender, target, sig);
	} else if(pid == 0) {
		// TODO implement process groups
	} else if(pid == -1) {
		// TODO implement process groups
	} else {
		// TODO implement process groups
	}

	return -1;
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
	print("syscall: [pid %x] sigpending: set {%x}\n", CORE_LOCAL->pid, set);
#endif

	regs->rax = sigpending(set);
}

void syscall_sigprocmask(struct registers *regs) {
	int how = regs->rdi;
	const sigset_t *set = (void*)regs->rsi;
	sigset_t *oldset = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] sigprocmask: how {%x}, set {%x}, oldset {%x}\n", CORE_LOCAL->pid, how, set, oldset);
#endif

	regs->rax = sigprocmask(how, set, oldset);
}

void syscall_kill(struct registers *regs) {
	pid_t pid = regs->rdi;
	int sig = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] kill: pid {%x}, sig {%x}\n", CORE_LOCAL->pid, pid, sig);
#endif

	regs->rax = kill(pid, sig);
}
