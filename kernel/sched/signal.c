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

	struct signal_queue *queue = &CURRENT_THREAD->signal_queue;

	spinlock_irqsave(&task->sig_lock);

	struct sigaction *current_action = &task->sigactions[sig - 1];

	if(old) {
		*old = *current_action;
	}

	if(act) {
		*current_action = *act;
		current_action->sa_mask &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP));

		spinlock_irqsave(&queue->siglock);

		if(act->handler.sa_sigaction == SIG_IGN && queue->sigpending & (1 << sig)) {
			queue->sigpending &= ~(1 << sig);
		}

		spinrelease_irqsave(&queue->siglock);
	}

	spinrelease_irqsave(&task->sig_lock);
	return 0;
}

int sigpending(sigset_t *set) {
	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic("");
	}

	struct signal_queue *queue = &thread->signal_queue;

	spinlock_irqsave(&queue->siglock);
	*set = queue->sigpending;
	spinrelease_irqsave(&queue->siglock);

	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic("");
	}

	struct signal_queue *queue = &thread->signal_queue;

	spinlock_irqsave(&queue->siglock);

	if(oldset) {
		*oldset = queue->sigmask;
	}

	if(set) {
		switch(how) {
			case SIG_BLOCK:
				queue->sigmask |= *set;
				break;
			case SIG_UNBLOCK:
				queue->sigmask &= ~(*set);
				break;
			case SIG_SETMASK:
				queue->sigmask = *set;
				break;
			default:
				set_errno(EINVAL);
				spinrelease_irqsave(&queue->siglock);
				return -1;
		}
	}

	spinrelease_irqsave(&queue->siglock);

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

int signal_send_thread(struct sched_thread *sender, struct sched_thread *target, int sig) {
	if(signal_is_valid(sig) == -1 && sig != 0) {
		set_errno(EINVAL);
		return -1;
	}

	struct sched_task *sender_task = NULL;
	if(sender) {
		sender_task = target->task;
	}
	struct sched_task *target_task = target->task;

	struct signal_queue *queue = &target->signal_queue;

	spinlock_irqsave(&target_task->sig_lock);
	spinlock_irqsave(&queue->siglock);

	if(sender != NULL && signal_check_permissions(sender_task, target_task) == -1) {
		set_errno(EPERM);
		spinrelease_irqsave(&queue->siglock);
		spinrelease_irqsave(&target_task->sig_lock);
		return -1;
	}

	if(sig != SIGSTOP && sig != SIGKILL) {
		if(target_task->sigactions[sig - 1].handler.sa_sigaction == SIG_IGN) {
			spinrelease_irqsave(&queue->siglock);
			spinrelease_irqsave(&target_task->sig_lock);
			return 0;
		}
	}

	struct signal_queue *signal_queue = &target->signal_queue;
	struct signal *signal = &signal_queue->queue[sig - 1];

	signal->refcnt = 1;
	signal->siginfo = alloc(sizeof(struct siginfo));
	signal->sigaction = &target_task->sigactions[sig - 1];
	signal->trigger = waitq_alloc(&queue->waitq, EVENT_SIGNAL);
	signal->queue = signal_queue;
	signal_queue->sigpending |= SIGMASK(sig);

	spinrelease_irqsave(&queue->siglock);
	spinrelease_irqsave(&target_task->sig_lock);

	return 0;
}

int signal_send_group(struct sched_thread *sender, struct process_group *target, int sig) {
	for(size_t i = 0; i < target->process_list.length; i++) {
		pid_t pid = target->process_list.data[i]->pid;

		struct sched_thread *thread = sched_translate_tid(pid, 0);
		if(!thread) {
			set_errno(ESRCH);
			return -1;
		}

		signal_send_thread(sender, thread, sig);
	}

	return 0;
}

static void signal_default_action(int signo) {
	int status = WSIGNALED_CONSTRUCT(signo);
	switch(signo) {
		case SIGHUP:
		case SIGINT:
		case SIGQUIT:
		case SIGILL:
		case SIGTRAP:
		case SIGBUS:
		case SIGFPE:
		case SIGKILL:
		case SIGUSR1:
		case SIGSEGV:
		case SIGUSR2:
		case SIGPIPE:
		case SIGALRM:
		case SIGSTKFLT:
		case SIGXCPU:
		case SIGXFSZ:
		case SIGVTALRM:
		case SIGPROF:
		case SIGSYS:
			return task_terminate(CURRENT_TASK, status);
		case SIGCONT:
		case SIGSTOP:
		case SIGTTIN:
		case SIGTTOU:
		case SIGTSTP:
			return;
		case SIGCHLD:
		case SIGWINCH:
			return;
	}
}

int signal_dispatch(struct sched_thread *thread, struct registers *state) {
	struct signal_queue *queue = &thread->signal_queue;

	spinlock_irqsave(&queue->siglock);
	if(queue->sigpending == 0) {
		spinrelease_irqsave(&queue->siglock);
		return -1;
	}

	if(((thread->signal_queue.sigpending & SIGMASK(SIGKILL)))) {
		signal_default_action(SIGKILL);
		panic("");
	}

	if((thread->signal_queue.sigpending & SIGMASK(SIGSTOP))) {
		signal_default_action(SIGSTOP);
		panic("");
	}

	for(size_t i = 1; i <= SIGNAL_MAX; i++) {
		if(((thread->signal_queue.sigpending & SIGMASK(i)) && !(thread->signal_queue.sigmask & SIGMASK(i)))) {
			struct signal *signal = &thread->signal_queue.queue[i - 1];
			struct sigaction *action = signal->sigaction;

			spinlock_irqsave(&CURRENT_TASK->sig_lock);
			if(action->handler.sa_sigaction == SIG_DFL) {
				thread->signal_queue.sigpending &= ~SIGMASK(i);
				signal_default_action(i);
				spinrelease_irqsave(&CURRENT_TASK->sig_lock);
				break;
			}

			thread->regs.rsp -= 128;
			thread->regs.rsp &= -16ll;

			thread->regs.rsp -= sizeof(struct siginfo);
			struct siginfo *siginfo = (void*)thread->regs.rsp;
			*siginfo = *signal->siginfo;

			thread->regs.rsp -= sizeof(struct registers);
			struct registers *ucontext = (void*)thread->regs.rsp;
			*ucontext = *state;

			thread->regs.rsp -= sizeof(uint64_t);
			*(uint64_t*)thread->regs.rsp = (uint64_t)action->sa_restorer;

			if(action->sa_flags & SA_SIGINFO) {
				thread->regs.rip = (uint64_t)action->handler.sa_sigaction;
				thread->regs.rdi = signal->signum;
				thread->regs.rsi = (uint64_t)siginfo;
				thread->regs.rdx = (uint64_t)ucontext;
			} else {
				thread->regs.rip = (uint64_t)action->handler.sa_sigaction;
				thread->regs.rdi = signal->signum;
			}

			thread->signal_queue.sigpending &= ~SIGMASK(i);

			spinrelease_irqsave(&CURRENT_TASK->sig_lock);

			break;
		}
	}

	spinrelease_irqsave(&queue->siglock);
	return 0;
}

int signal_wait(struct signal_queue *signal_queue, sigset_t mask, struct timespec *timespec) {
	if(timespec) {
		waitq_set_timer(&signal_queue->waitq, *timespec);
	}

	spinlock_irqsave(&signal_queue->siglock);
	for(size_t i = 1; i <= SIGNAL_MAX; i++) {
		if(mask & SIGMASK(i)) {
			struct signal *signal = &signal_queue->queue[i - 1];

			if(signal->trigger == NULL) {
				signal->trigger = waitq_alloc(&signal_queue->waitq, EVENT_SIGNAL);
			}

			waitq_add(&signal_queue->waitq, signal->trigger);
		}
	}

	int ret = waitq_wait(&signal_queue->waitq, EVENT_SIGNAL);
	waitq_release(&signal_queue->waitq, EVENT_SIGNAL);

	if(ret == -1) {
		return -1;
	}

	waitq_release(&signal_queue->waitq, EVENT_SIGNAL);

	spinlock_irqsave(&signal_queue->siglock);

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

	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	if(pid > 0) {
		struct sched_thread *target = sched_translate_tid(pid, 0);
		if(target == NULL) {
			set_errno(ESRCH);
			return -1;
		}

		signal_send_thread(sender, target, sig);
	} else if(pid == 0) {
		signal_send_group(sender, current_task->group, sig);
	} else if(pid == -1) {
		// TODO: Send signal to ALL processes in the system.
		signal_send_group(sender, current_task->group, sig);
	} else {
		struct session *session = current_task->session;
		struct process_group *group = hash_table_search(&session->group_list, &pid, sizeof(pid));

		if(group == NULL) {
			set_errno(ESRCH);
			return -1;
		}

		for(size_t i = 0; i < group->process_list.length; i++) {
			pid_t pid = group->process_list.data[i]->pid;

			struct sched_thread *target = sched_translate_tid(pid, 0);
			if(target == NULL) {
				set_errno(ESRCH);
				return -1;
			}

			signal_send_thread(sender, target, sig);
		}
	}

	return 0;
}

void syscall_sigreturn(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] sigreturn\n", CORE_LOCAL->pid);
#endif

	struct registers *context = (void*)regs->rsp;
	regs->rsp += sizeof(struct registers);

	struct siginfo *siginfo = (void*)regs->rsp;
	regs->rsp += sizeof(struct siginfo);

	struct sched_thread *thread = CURRENT_THREAD;
	thread->regs = *context;

	if(context->cs & 0x3) {
		sched_yield();
	} else {
		thread->signal_release_block = true;
		sched_yield();
	}
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

void syscall_pause(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] pause\n", CORE_LOCAL->pid);
#endif

	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic("");
	}

	struct signal_queue *queue = &thread->signal_queue;

	signal_wait(queue, ~0ull, NULL);

	set_errno(EINTR);
	regs->rax = -1;
}

void syscall_sigsuspend(struct registers *regs) {
	sigset_t *mask = (void*)regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] pause\n", CORE_LOCAL->pid);
#endif

	struct sched_thread *thread = CURRENT_THREAD;
	if(thread == NULL) {
		panic("");
	}

	struct signal_queue *queue = &thread->signal_queue;

	sigset_t save;

	sigprocmask(SIG_SETMASK, mask, &save);
	signal_wait(queue, ~(*mask), NULL);
	sigprocmask(SIG_SETMASK, &save, mask);

	set_errno(EINTR);
	regs->rax = -1;
}
