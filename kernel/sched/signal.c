#include <sched/signal.h>
#include <sched/sched.h>
#include <mm/mmap.h>
#include <mm/pmm.h>
#include <debug.h>
#include <errno.h>

static void sigreturn_default(int release_block);

int sigaction(int sig, const struct sigaction *act, struct sigaction *old) {
	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	if(signal_is_valid(sig) == -1 || (sig == SIGKILL || sig == SIGSTOP)) {
		set_errno(EINVAL);
		return -1;
	}

	struct signal_queue *queue = &CURRENT_TASK->signal_queue;

	spinlock_irqsave(&task->sig_lock);

	struct sigaction *current_action = &task->sigactions[sig - 1];

	if(old) {
		*old = *current_action;
	}

	if(act) {
		*current_action = *act;
		current_action->sa_mask &= ~(SIGMASK(SIGKILL) | SIGMASK(SIGSTOP));

		//print("sigaction [pid %d, tid %d]: signum %x: handler %x\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sig, act->handler);

		spinlock_irqsave(&queue->siglock);

		if(act->handler.sa_sigaction == SIG_IGN && queue->sigpending & (1ull << sig)) {
			queue->sigpending &= ~(1 << sig);
		}

		spinrelease_irqsave(&queue->siglock);
	}

	spinrelease_irqsave(&task->sig_lock);
	return 0;
}

int sigpending(sigset_t *set) {
	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	struct signal_queue *queue = &task->signal_queue;

	spinlock_irqsave(&queue->siglock);
	*set = queue->sigpending;
	spinrelease_irqsave(&queue->siglock);

	return 0;
}

int sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	struct signal_queue *queue = &task->signal_queue;

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

	queue->sigmask &= ~(SIGMASK(SIGSTOP) | SIGMASK(SIGKILL));
	spinrelease_irqsave(&queue->siglock);

	return 0;
}

int signal_check_permissions(struct task *sender, struct task *target) {
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

int signal_send_task(struct task *sender, struct task *target, int sig) {
	if(signal_is_valid(sig) == -1 && sig != 0) {
		set_errno(EINVAL);
		return -1;
	}

	struct signal_queue *queue = &target->signal_queue;

	spinlock_irqsave(&target->sig_lock);
	spinlock_irqsave(&queue->siglock);

	if(sender != NULL && signal_check_permissions(sender, target) == -1) {
		set_errno(EPERM);
		spinrelease_irqsave(&queue->siglock);
		spinrelease_irqsave(&target->sig_lock);
		return -1;
	}

	if(sig != SIGSTOP && sig != SIGKILL) {
		if(target->sigactions[sig - 1].handler.sa_sigaction == SIG_IGN) {
			spinrelease_irqsave(&queue->siglock);
			spinrelease_irqsave(&target->sig_lock);
			return 0;
		}
	}

	struct signal_queue *signal_queue = &target->signal_queue;
	struct signal *signal = &signal_queue->queue[sig - 1];

	signal->refcnt = 1;
	signal->signum = sig;
	signal->siginfo = alloc(sizeof(struct siginfo));
	signal->trigger = waitq_alloc(&queue->waitq, EVENT_SIGNAL);
	signal->queue = signal_queue;
	signal_queue->sigpending |= SIGMASK(sig);

	target->dispatch_ready = true;
	target->dispatch_ready = true;

	spinrelease_irqsave(&queue->siglock);
	spinrelease_irqsave(&target->sig_lock);

	return 0;
}

int signal_send_group(struct task *sender, struct process_group *target, int sig) {
	for(size_t i = 0; i < target->process_list.length; i++) {
		pid_t pid = target->process_list.data[i]->id.pid;

		struct task *task = sched_translate_pid(CORE_LOCAL->nid, pid, 0);

		if(!task) {
			set_errno(ESRCH);
			return -1;
		}

		signal_send_task(sender, task, sig);
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
		case SIGSTOP:
		case SIGTTIN:
		case SIGTTOU:
		case SIGTSTP:
			task_stop(CURRENT_TASK, signo);
			break;
		case SIGCONT:
			task_continue(CURRENT_TASK);
			break;
		case SIGCHLD:
		case SIGWINCH:
	}

	sigreturn_default(false);
}

int signal_dispatch(struct task *task, struct registers *state) {
	struct signal_queue *queue = &task->signal_queue;

	spinlock_irqsave(&queue->siglock);

	if(queue->active == false) {
		spinrelease_irqsave(&queue->siglock);
		return -1;
	}

	if(queue->sigpending == 0) {
		spinrelease_irqsave(&queue->siglock);
		return -1;
	}

	for(size_t i = 1; i <= SIGNAL_MAX; i++) {
		if(((task->signal_queue.sigpending & SIGMASK(i)) && !(task->signal_queue.sigmask & SIGMASK(i)))) {
			struct signal *signal = &task->signal_queue.queue[i - 1];
			struct sigaction *action = &task->sigactions[signal->signum - 1];

			spinlock_irqsave(&CURRENT_TASK->sig_lock);

			task->signal_queue.sigpending &= ~SIGMASK(i);

			print("dispatching signal %d with action %x\n", i, action->handler.sa_sigaction);

			if(action->handler.sa_sigaction == SIG_ERR) {
				spinrelease_irqsave(&CURRENT_TASK->sig_lock);
				spinrelease_irqsave(&queue->siglock);
				return -1;
			} else if(action->handler.sa_sigaction == SIG_IGN) {
				spinrelease_irqsave(&CURRENT_TASK->sig_lock);
				continue;
			}

			struct ucontext context;

			task->signal_queue.sigpending &= ~SIGMASK(i);

			if(action->handler.sa_sigaction == SIG_DFL) {
				struct stack stack = {
					.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + HIGH_VMA + THREAD_KERNEL_STACK_SIZE,
					.size = THREAD_KERNEL_STACK_SIZE,
					.flags = 0
				};

				context.stack = stack;
				context.registers = *state;
				context.signum = signal->signum;

				memset8((void*)state, 0, sizeof(*state));

				state->ss = 0x30;
				state->rsp = stack.sp;
				state->rflags = 0x202;
				state->cs = 0x28;
				state->rip = (uint64_t)signal_default_action;

				state->rdi = signal->signum;

				task->signal_context = context;

				struct stack tmp = task->kernel_stack;
				task->kernel_stack = task->signal_kernel_stack;
				task->signal_kernel_stack = tmp;

				tmp = task->user_stack;
				task->signal_user_stack = tmp;

				spinrelease_irqsave(&CURRENT_TASK->sig_lock);
				spinrelease_irqsave(&queue->siglock);

				return 0;
			}

			struct stack stack = {
				.sp = (uint64_t)mmap(CORE_LOCAL->page_table,
						NULL,
						THREAD_USER_STACK_SIZE,
						MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_USER,
						MMAP_MAP_ANONYMOUS,
						0,
						0) + THREAD_USER_STACK_SIZE,
				.size = THREAD_USER_STACK_SIZE,
				.flags = 0
			};

			context.stack = stack;
			context.registers = *state;
			context.signum = signal->signum;

			memset8((void*)state, 0, sizeof(*state));

			stack.sp -= 128;
			stack.sp &= -16ll;

			stack.sp -= sizeof(struct siginfo);
			struct siginfo *siginfo = (void*)stack.sp;
			*siginfo = *signal->siginfo;

			siginfo->si_signo = signal->signum;

			stack.sp -= sizeof(struct registers);
			struct ucontext *ucontext = (void*)stack.sp;
			*ucontext = context;

			stack.sp -= sizeof(uint64_t);
			*(uint64_t*)stack.sp = (uint64_t)action->sa_restorer;

			task->signal_context = context;

			state->ss = 0x3b;
			state->rsp = stack.sp;
			state->rflags = 0x202;
			state->cs = 0x43;
			state->rip = (uint64_t)action->handler.sa_sigaction;

			state->rdi = signal->signum;

			if(action->sa_flags & SA_SIGINFO) {
				state->rsi = (uint64_t)siginfo;
				state->rdx = (uint64_t)ucontext;
			}

			struct stack tmp = task->kernel_stack;
			task->kernel_stack = task->signal_kernel_stack;
			task->signal_kernel_stack = tmp;

			tmp = task->user_stack;
			task->user_stack = stack;
			task->signal_user_stack = tmp;

			spinrelease_irqsave(&CURRENT_TASK->sig_lock);

			break;
		}
	}

	spinrelease_irqsave(&queue->siglock);

	return 0;
}

int signal_wait(struct signal_queue *signal_queue, sigset_t mask, struct timespec *timespec) {
	if(timespec) {
		waitq_set_timer(&signal_queue->waitq, timespec);
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
	spinrelease_irqsave(&signal_queue->siglock);

	int ret = waitq_wait(&signal_queue->waitq, EVENT_SIGNAL);
	waitq_release(&signal_queue->waitq, EVENT_SIGNAL);

	if(ret == -1) {
		return -1;
	}

	waitq_release(&signal_queue->waitq, EVENT_SIGNAL);

	return 0;
}

int kill(pid_t pid, int sig) {
	if(signal_is_valid(sig) == -1) {
		set_errno(EINVAL);
		return -1;
	}

	struct task *sender = CURRENT_TASK;
	if(sender == NULL) {
		panic("");
	}

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	if(pid > 0) {
		struct task *target = sched_translate_pid(CORE_LOCAL->nid, pid, 0);
		if(target == NULL) {
			set_errno(ESRCH);
			return -1;
		}

		signal_send_task(sender, target, sig);
	} else if(pid == 0) {
		signal_send_group(sender, current_task->group, sig);
	} else if(pid == -1) {
		signal_send_group(sender, current_task->group, sig);
	} else {
		struct session *session = current_task->session;
		struct process_group *group = hash_table_search(&session->group_list, &pid, sizeof(pid));

		if(group == NULL) {
			set_errno(ESRCH);
			return -1;
		}

		for(size_t i = 0; i < group->process_list.length; i++) {
			pid_t pid = group->process_list.data[i]->id.pid;

			struct task *target = sched_translate_pid(CORE_LOCAL->nid, pid, 0);
			if(target == NULL) {
				set_errno(ESRCH);
				return -1;
			}

			signal_send_task(sender, target, sig);
		}
	}

	return 0;
}

static void sigreturn_default(int release_block) {
	asm volatile ("cli");

	struct task *task = CURRENT_TASK;

	struct signal_queue *signal_queue = &task->signal_queue;

	spinlock_irqsave(&signal_queue->siglock);

	struct signal *signal = &signal_queue->queue[task->signal_context.signum - 1];
	waitq_wake(signal->trigger);

	spinrelease_irqsave(&signal_queue->siglock);

	struct stack *stack = &task->signal_context.stack;
	struct registers *context = &task->signal_context.registers;

	pmm_free(stack->sp - HIGH_VMA - stack->size, DIV_ROUNDUP(stack->size, PAGE_SIZE));

	task->regs = *context;

	if(release_block) {
		task->blocking = false;
		task->signal_release_block = true;
	}

	task->dispatch_ready = false;
	task->dispatch_ready = false;

	CORE_LOCAL->user_stack = task->user_stack.sp;
	CORE_LOCAL->kernel_stack = task->kernel_stack.sp;

	if(context->cs & 0x3) {
		swapgs();
	}

	asm volatile (
		"mov %0, %%rsp\n\t"
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%r11\n\t"
		"pop %%r10\n\t"
		"pop %%r9\n\t"
		"pop %%r8\n\t"
		"pop %%rsi\n\t"
		"pop %%rdi\n\t"
		"pop %%rbp\n\t"
		"pop %%rdx\n\t"
		"pop %%rcx\n\t"
		"pop %%rbx\n\t"
		"pop %%rax\n\t"
		"addq $16, %%rsp\n\t"
		"iretq\n\t"
		:: "r" (context)
	);
}

void syscall_sigreturn(struct registers*) {
#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] sigreturn\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif
	asm volatile ("cli");

	struct task *task = CURRENT_TASK;

	struct signal_queue *signal_queue = &task->signal_queue;

	spinlock_irqsave(&signal_queue->siglock);

	struct signal *signal = &signal_queue->queue[task->signal_context.signum - 1];
	waitq_wake(signal->trigger);

	spinrelease_irqsave(&signal_queue->siglock);

	struct stack *stack = &task->signal_context.stack;
	struct registers *context = &task->signal_context.registers;

	task->regs = *context;
	munmap(task->page_table, (void*)(stack->sp - stack->size), stack->size);

	task->blocking = false;
	task->signal_release_block = true;

	task->dispatch_ready = false;
	task->dispatch_ready = false;

	struct stack tmp = task->kernel_stack;
	task->kernel_stack = task->signal_kernel_stack;
	task->signal_kernel_stack = tmp;

	tmp = task->user_stack;
	task->user_stack = task->signal_user_stack;
	task->signal_user_stack = tmp;

	CORE_LOCAL->user_stack = task->user_stack.sp;
	CORE_LOCAL->kernel_stack = task->kernel_stack.sp;

	if(context->cs & 0x3) {
		swapgs();
	}

	asm volatile (
		"mov %0, %%rsp\n\t"
		"pop %%r15\n\t"
		"pop %%r14\n\t"
		"pop %%r13\n\t"
		"pop %%r12\n\t"
		"pop %%r11\n\t"
		"pop %%r10\n\t"
		"pop %%r9\n\t"
		"pop %%r8\n\t"
		"pop %%rsi\n\t"
		"pop %%rdi\n\t"
		"pop %%rbp\n\t"
		"pop %%rdx\n\t"
		"pop %%rcx\n\t"
		"pop %%rbx\n\t"
		"pop %%rax\n\t"
		"addq $16, %%rsp\n\t"
		"iretq\n\t"
		:: "r" (context)
	);
}

int signal_is_blocked(struct task *task, int sig) {
	if(signal_is_valid(sig) == -1) {
		return -1;
	}

	spinlock_irqsave(&task->signal_queue.siglock);
	if(task->signal_queue.sigmask & SIGMASK(sig)) {
		spinrelease_irqsave(&task->signal_queue.siglock);
		return 0;
	}

	spinrelease_irqsave(&task->signal_queue.siglock);
	return -1;
}

int signal_is_ignored(struct task *task, int sig) {
	if(signal_is_valid(sig) == -1) {
		return -1;
	}

	spinlock_irqsave(&task->sig_lock);
	struct sigaction *act = &task->sigactions[sig - 1];
	if(act->handler.sa_handler == SIG_IGN) {
		spinrelease_irqsave(&task->sig_lock);
		return 0;
	}

	spinrelease_irqsave(&task->sig_lock);
	return -1;
}

void syscall_sigaction(struct registers *regs) {
	int sig = regs->rdi;
	const struct sigaction *act = (void*)regs->rsi;
	struct sigaction *old = (void*)regs->rdx;

#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] sigaction: signum {%x}, act {%x}, old {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, sig, act, old);
#endif

	regs->rax = sigaction(sig, act, old);
}

void syscall_sigpending(struct registers *regs) {
	sigset_t *set = (void*)regs->rdi;

#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] sigpending: set {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, set);
#endif

	regs->rax = sigpending(set);
}

void syscall_sigprocmask(struct registers *regs) {
	int how = regs->rdi;
	const sigset_t *set = (void*)regs->rsi;
	sigset_t *oldset = (void*)regs->rdx;

#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] sigprocmask: how {%x}, set {%x}, oldset {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, how, set, oldset);
#endif

	regs->rax = sigprocmask(how, set, oldset);
}

void syscall_kill(struct registers *regs) {
	pid_t pid = regs->rdi;
	int sig = regs->rsi;

#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] kill: pid {%x}, sig {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, pid, sig);
#endif

	regs->rax = kill(pid, sig);
}

void syscall_pause(struct registers *regs) {
#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] pause\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif

	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	struct signal_queue *queue = &task->signal_queue;

	signal_wait(queue, ~0ull, NULL);

	set_errno(EINTR);
	regs->rax = -1;
}

void syscall_sigsuspend(struct registers *regs) {
	sigset_t *mask = (void*)regs->rdi;

#if defined(SYSCALL_DEBUG_SIGNAL) || defined(SYSCALL_DEBUG_ALL)
	print("syscall: [pid %x, tid %x] pause\n", CORE_LOCAL->pid, CORE_LOCAL->tid);
#endif

	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	struct signal_queue *queue = &task->signal_queue;

	sigset_t save;

	sigprocmask(SIG_SETMASK, mask, &save);
	signal_wait(queue, ~(*mask), NULL);
	sigprocmask(SIG_SETMASK, &save, mask);

	set_errno(EINTR);
	regs->rax = -1;
}
