#include <sched/sched.h>
#include <int/apic.h>
#include <vector.h>
#include <cpu.h>
#include <mm/pmm.h>
#include <string.h>
#include <debug.h>
#include <elf.h>
#include <mm/mmap.h>
#include <types.h>
#include <errno.h>
#include <fs/fd.h>
#include <time.h>
#include <lock.h>

static struct hash_table namespace_list;

static struct bitmap nid_bitmap = {
	.data = NULL,
	.size = 0,
	.resizable = true
};

struct spinlock sched_lock;

struct task *sched_translate_pid(nid_t nid, pid_t pid) {
	struct pid_namespace *namespace = hash_table_search(&namespace_list, &nid, sizeof(nid));
	if(namespace == NULL) {
		return NULL;
	}

	return hash_table_search(&namespace->process_list, &pid, sizeof(pid));
}

struct task *find_next_task() {
	struct task *ret = NULL;

	for(size_t i = 0; i < namespace_list.capacity; i++) {
		struct pid_namespace *namespace = namespace_list.data[i];
		if(namespace == NULL) {
			continue;
		}

		for(size_t i = 0, cnt = 0; i < namespace->process_list.capacity; i++) {
			struct task *task = namespace->process_list.data[i];
			if(task == NULL) {
				continue;
			}

			task->idle_cnt++;

			//print("pid: %x: status: %x: dispatch: %x\n", task->pid, task->sched_status, task->dispatch_ready);

			if((task->sched_status == TASK_WAITING || task->dispatch_ready == true) && cnt < task->idle_cnt) {
				cnt = task->idle_cnt;
				ret = task;
			}
		}
	}

	return ret;
}

void sched_idle() {
	xapic_write(XAPIC_EOI_OFF, 0);
	spinrelease_irqsave(&sched_lock);

	for(;;) {
		asm volatile ("hlt");
	}
}

void reschedule(struct registers *regs, void*) {
	if(__atomic_test_and_set(&sched_lock, __ATOMIC_ACQUIRE)) {
		return;
	}

	struct task *next_task = find_next_task();
	if(next_task == NULL) {
		if(CORE_LOCAL->tid != -1 && CORE_LOCAL->pid != -1) {
			signal_dispatch(CURRENT_TASK, regs);
			spinrelease_irqsave(&sched_lock);
			return;
		}
		sched_idle();
	}

	if(CORE_LOCAL->tid != -1 && CORE_LOCAL->pid != -1) {
		struct task *last_task = CURRENT_TASK;
		if(last_task == NULL) {
			sched_idle();
		}

		if(last_task->sched_status != TASK_YIELD) {
			last_task->sched_status = TASK_WAITING;
		}

		if(last_task->sched_status != TASK_YIELD) {
			last_task->sched_status = TASK_WAITING;
		}

		last_task->errno = CORE_LOCAL->errno;
		last_task->regs = *regs;
		last_task->user_fs_base = get_user_fs();
		last_task->user_gs_base = get_user_gs();
		last_task->user_stack.sp = CORE_LOCAL->user_stack;
	}

	CORE_LOCAL->pid = next_task->pid;
	CORE_LOCAL->tid = next_task->tid;
	CORE_LOCAL->nid = next_task->namespace->nid;
	CORE_LOCAL->errno = next_task->errno;

	CORE_LOCAL->page_table = next_task->page_table;

	vmm_init_page_table(CORE_LOCAL->page_table);

	signal_dispatch(next_task, &next_task->regs);

	CORE_LOCAL->kernel_stack = next_task->kernel_stack.sp;
	CORE_LOCAL->user_stack = next_task->user_stack.sp;

	next_task->idle_cnt = 0;
	next_task->idle_cnt = 0;
	next_task->sched_status = TASK_RUNNING;
	next_task->sched_status = TASK_RUNNING;

	set_user_fs(next_task->user_fs_base);
	set_user_gs(next_task->user_gs_base);

	if(next_task->regs.cs & 0x3) {
		swapgs();
	}

	//print("rescheduling to %x:%x to %x:%x [stack] %x:%x\n", next_task->regs.cs, next_task->regs.rip, next_task->pid, next_task->tid, next_task->regs.ss, next_task->regs.rsp);

	xapic_write(XAPIC_EOI_OFF, 0);
	spinrelease_irqsave(&sched_lock);

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
		:: "r" (&next_task->regs)
	);
}

void sched_dequeue(struct task *task) {
	spinlock_irqsave(&sched_lock);

	if(task) {
		task->sched_status = TASK_YIELD;
	}

	spinrelease_irqsave(&sched_lock);
}

void sched_dequeue_and_yield(struct task *task) {
	sched_dequeue(task);
	sched_yield();
}

void sched_requeue(struct task *task) {
	spinlock_irqsave(&sched_lock);

	task->sched_status = TASK_WAITING;
	task->idle_cnt = TASK_MAX_PRIORITY;

	spinrelease_irqsave(&sched_lock);
}

void sched_requeue_and_yield(struct task *task) {
	asm volatile ("cli");

	sched_requeue(task);

	xapic_write(XAPIC_ICR_OFF + 0x10, CORE_LOCAL->apic_id << 24);
	xapic_write(XAPIC_ICR_OFF, 32);

	asm volatile ("sti");

	for(;;) {
		asm volatile ("hlt");
	}
}

void sched_yield() {
	asm volatile ("sti");

	xapic_write(XAPIC_ICR_OFF + 0x10, CORE_LOCAL->apic_id << 24);
	xapic_write(XAPIC_ICR_OFF, 32);

	for(;;) {
		asm volatile ("hlt");
	}
}

struct task *sched_default_task(struct pid_namespace *namespace) {
	struct task *task = alloc(sizeof(struct task));

	task->namespace = namespace;
	task->pid = bitmap_alloc(&namespace->pid_bitmap);

	task->fd_table = alloc(sizeof(struct fd_table));
	task->fd_table->fd_bitmap.resizable = true;

	task->sched_status = TASK_YIELD;

	task->waitq = alloc(sizeof(struct waitq));
	task->status_trigger = waitq_alloc(task->waitq, EVENT_PROCESS_STATUS);

	task->real_uid = 0;
	task->effective_uid = 0;
	task->saved_uid = 0;

	task->real_gid = 0;
	task->effective_gid = 0;
	task->saved_gid = 0;

	task->page_table = alloc(sizeof(struct page_table));
	vmm_default_table(task->page_table);

	task->umask = 022;

	task->sigactions = alloc(sizeof(struct sigaction) * SIGNAL_MAX);

	for(int i = 0; i < SIGNAL_MAX; i++) {
		struct sigaction *sa = &task->sigactions[i];
		sa->handler.sa_sigaction = SIG_DFL;
	}

	if(CURRENT_TASK != NULL) {
		task->parent = CURRENT_TASK;
	} else {
		task->parent = NULL;
	}

	task->kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->kernel_stack.size = THREAD_KERNEL_STACK_SIZE;

	task->signal_kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->signal_kernel_stack.size = THREAD_KERNEL_STACK_SIZE;

	hash_table_push(&namespace->process_list, &task->pid, task, sizeof(task->pid));

	return task;
}

struct pid_namespace *sched_default_namespace() {
	struct pid_namespace *namespace = alloc(sizeof(struct pid_namespace));

	namespace->nid = bitmap_alloc(&nid_bitmap);
	namespace->pid_bitmap = (struct bitmap) {
		.data = NULL,
		.size = 0,
		.resizable = true
	};

	hash_table_push(&namespace_list, &namespace->nid, namespace, sizeof(namespace->nid));

	return namespace;
}

int sched_task_init(struct task *task, char **envp, char **argv) {
	spinlock_irqsave(&sched_lock);

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	if(task->program.loaded == false) {
		panic("");
	}

	CORE_LOCAL->pid = task->pid;
	vmm_init_page_table(task->page_table);

	task->regs.rip = task->program.entry;
	task->regs.cs = 0x43;
	task->regs.rflags = 0x202;
	task->regs.ss = 0x3b;

	task->user_stack.sp = (uint64_t)mmap(
			task->page_table,
			NULL,
			THREAD_USER_STACK_SIZE,
			MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_USER,
			MMAP_MAP_ANONYMOUS,
			0,
			0
	) + THREAD_USER_STACK_SIZE;
	task->user_stack.size = THREAD_USER_STACK_SIZE;

	int ret = program_place_parameters(&task->program, envp, argv);

	CORE_LOCAL->pid = current_task->pid;
	vmm_init_page_table(current_task->page_table);

	spinrelease_irqsave(&sched_lock);

	if(ret == -1) {
		return -1;
	}

	return 0;
}

int sched_load_program(struct task *task, const char *path) {
	spinlock_irqsave(&sched_lock);

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	task->program.task = task;

	vmm_init_page_table(task->page_table);
	CORE_LOCAL->pid = task->pid;

	int ret = program_load(&task->program, path);
	if(ret == -1) {
		spinrelease_irqsave(&sched_lock);
		return -1;
	}

	vmm_init_page_table(current_task->page_table);
	CORE_LOCAL->pid = current_task->pid;

	spinrelease_irqsave(&sched_lock);

	return 0;
}

int task_create_session(struct task *task, bool force) {
	if(!force && task->group->pid_leader == task->pid) {
		set_errno(EPERM);
		return -1;
	}

	struct session *session = alloc(sizeof(struct session));
	struct process_group *group = alloc(sizeof(struct process_group));

	pid_t sid = task->pid;
	pid_t pgid = task->pid;

	session->sid = sid;
	session->pgid_leader = pgid;

	group->pgid = pgid;
	group->pid_leader = task->pid;
	group->leader = task;
	group->session = session;
	VECTOR_PUSH(group->process_list, task);
	hash_table_push(&session->group_list, &group->pgid, group, sizeof(session->pgid_leader));

	task->session = session;
	task->group = group;

	return 0;
}

int task_setpgid(struct task *task, pid_t pgid) {
	if(task->group->pgid == pgid) {
		return 0;
	}

	if((CURRENT_TASK->session != task->session) || (task->session->pgid_leader == task->pid)) {
		set_errno(EPERM);
		return -1;
	}

	if(task->pid != CURRENT_TASK->pid) {
		if(task->has_execved || task->parent->pid != CURRENT_TASK->pid) {
			set_errno(EPERM);
			return -1;
		}
	}

	struct session *session = task->session;
	struct process_group *target_group;

	target_group = alloc(sizeof(struct process_group));
	target_group->pgid = pgid;
	target_group->session = session;
	target_group->pid_leader = task->pid;
	target_group->leader = task;
	hash_table_push(&session->group_list, &target_group->pgid, target_group, sizeof(target_group->pgid));

	VECTOR_PUSH(target_group->process_list, task);
	task->group = target_group;

	return 0;
}

void syscall_waitpid(struct registers *regs) {
	int pid = regs->rdi;
	int *status = (int*)regs->rsi;
	int options = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] waitpid: pid {%x}, status {%x}, options {%x}\n", CURRENT_TASK->pid, pid, (uintptr_t)status, options);
#endif

	asm volatile ("cli");

	struct task *current_task = CURRENT_TASK;
	struct pid_namespace *namespace = current_task->namespace;

	for(size_t i = 0; i < current_task->zombies.length; i++) {
		struct task *zombie = current_task->zombies.data[i];

		if(pid < -1) {
			if(zombie->group->pgid != zombie->pid) {
				continue;
			}
		} else if(pid == 0) {
			if(zombie->group->pgid != current_task->group->pgid) {
				continue;
			}
		} else if(pid > 0) {
			if(zombie->pid != pid) {
				continue;
			}
		}

		if(status) {
			*status = zombie->process_status;
		}

		VECTOR_REMOVE_BY_VALUE(current_task->zombies, zombie);

		regs->rax = zombie->pid;
		return;
	}

	if((options & WNOHANG) == WNOHANG && current_task->zombies.length == 0) {
		regs->rax = 0;
		return;
	}

	VECTOR(struct task*) process_list = { 0 };

	if(pid < -1) {
		for(size_t i = 0; i < current_task->children.length; i++) {
			struct task *task = current_task->children.data[i];

			if(task->group->pgid == abs(pid)) {
				VECTOR_PUSH(process_list, task);
			}
		}
	} else if(pid == -1) {
		for(size_t i = 0; i < current_task->children.length; i++) {
			VECTOR_PUSH(process_list, current_task->children.data[i]);
		}
	} else if(pid == 0) {
		for(size_t i = 0; i < current_task->children.length; i++) {
			struct task *task = current_task->children.data[i];

			if(task->group->pgid == current_task->group->pgid) {
				VECTOR_PUSH(process_list, task);
			}
		}
	} else if(pid > 0) {
		VECTOR_PUSH(process_list, sched_translate_pid(namespace->nid, pid));
	}

	for(size_t i = 0; i < process_list.length; i++) {
		waitq_add(current_task->waitq, process_list.data[i]->status_trigger);
	}

do_wait:
	uint64_t ret = waitq_wait(current_task->waitq, EVENT_PROCESS_STATUS);
	waitq_release(current_task->waitq, EVENT_PROCESS_STATUS);

	if(ret == -1) {
		goto finish;
	}

	struct waitq_trigger *trigger = current_task->last_trigger;
	struct task *agent = trigger->agent_task;

	if(!(options & WUNTRACED) && WIFSTOPPED(agent->process_status)) goto do_wait;
	if(!(options & WCONTINUED) && WIFCONTINUED(agent->process_status)) goto do_wait;

	if(status != NULL) {
		*status = agent->process_status;
	}

	ret = agent->pid;
finish:
	for(size_t i = 0; i < process_list.length; i++) {
		waitq_remove(current_task->waitq, process_list.data[i]->status_trigger);
	}

	regs->rax = ret;
}

void task_terminate(struct task *task, int status) {
	asm volatile ("cli");

	for(size_t i = 0; i < task->fd_table->fd_bitmap.size; i++) {
		if(BIT_TEST(task->fd_table->fd_bitmap.data, i)) {
			fd_close(i);
		}
	}

	/*for(size_t i = 0; i < task->thread_list.capacity; i++) {
		struct sched_thread *thread = task->thread_list.data[i];

		if(thread) {
			thread->sched_status = TASK_YIELD;
			hash_table_delete(&task->thread_list, &thread->tid, sizeof(thread->tid));
		}
	}*/

	struct page_table *page_table = task->page_table;

	for(size_t i = 0; i < page_table->pages->capacity; i++) {
		struct page *page = page_table->pages->data[i];

		if(page) {
			hash_table_delete(page_table->pages, &page->vaddr, sizeof(page->vaddr));

			if((*page->reference) <= 1) { // shared page
				(*page->reference)--;
				continue;
			}

			pmm_free(page->paddr, 1);
		}
	}

	signal_send_task(NULL, task, SIGCHLD);

	struct task *parent = sched_translate_pid(task->namespace->nid, 1);

	for(size_t i = 0; i < task->children.length; i++) {
		struct task *child = task->children.data[i];

		child->status_trigger->waitq = parent->waitq;
		child->parent = parent;

		VECTOR_PUSH(parent->children, child);
	}

	for(size_t i = 0; i < task->zombies.length; i++) {
		struct task *zombie = task->zombies.data[i];

		zombie->status_trigger->waitq = parent->waitq;
		zombie->parent = parent;

		VECTOR_PUSH(parent->zombies, zombie);
	}

	VECTOR_REMOVE_BY_VALUE(task->parent->children, task);
	VECTOR_PUSH(task->parent->zombies, task);

	task->status_trigger->agent_task->process_status = status;
	waitq_wake(task->status_trigger);

	task->sched_status = TASK_YIELD;

	hash_table_delete(&task->namespace->process_list, &task->pid, sizeof(task->pid));

	CORE_LOCAL->pid = -1;
	CORE_LOCAL->tid = -1;

	asm volatile ("sti");

	sched_yield();
}


void task_stop(struct task *task, int sig) {
	// TODO: figure out why this doesn't work.
	//task->process_status = WSTOPPED_CONSTRUCT(sig);
	task->status_trigger->agent_task->process_status = WSTOPPED_CONSTRUCT(sig);
	signal_send_task(NULL, task, SIGCHLD);
	waitq_wake(task->status_trigger);
	sched_dequeue_and_yield(CURRENT_TASK);
}

void task_continue(struct task *task) {
	// TODO: figure out why this doesn't work.
	//task->process_status = WCONTINUED_CONSTRUCT;
	task->status_trigger->agent_task->process_status = WCONTINUED_CONSTRUCT;
	signal_send_task(NULL, task, SIGCHLD);
	waitq_wake(task->status_trigger);
	sched_requeue_and_yield(CURRENT_TASK);
}

void syscall_exit(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] exit\n", CURRENT_TASK->pid);
#endif
	struct task *task = CURRENT_TASK;
	if(task == NULL) {
		panic("");
	}

	task_terminate(task, WEXITED_CONSTRUCT(regs->rdi));
}

void syscall_execve(struct registers *regs) {
	char *_path = (char*)regs->rdi;
	char **_argv = (char**)regs->rsi;
	char **_envp = (char**)regs->rdx;

	int envp_cnt = 0;
	for(;;envp_cnt++) {
		if(_envp[envp_cnt] == NULL) {
			break;
		}
	}

	int argv_cnt = 0;
	for(;;argv_cnt++) {
		if(_argv[argv_cnt] == NULL) {
			break;
		}
	}

	char *path = alloc(strlen(_path) + 1);
	char **argv = alloc(sizeof(char*) * argv_cnt);
	char **envp = alloc(sizeof(char*) * envp_cnt);

	strcpy(path, _path);

	for(size_t i = 0; i < envp_cnt; i++) {
		envp[i] = alloc(strlen(_envp[i]));
		strcpy(envp[i], _envp[i]);
	}

	for(size_t i = 0; i < argv_cnt; i++) {
		argv[i] = alloc(strlen(_argv[i]));
		strcpy(argv[i], _argv[i]);
	}

#ifndef SYSCALL_DEBUG
	print("syscall: execve: path {%s}, argv {", path);

	for(size_t i = 0; i < argv_cnt; i++) {
		print("%s, ", argv[i]);
	}

	print("\b\b}, envp {");

	for(size_t i = 0; i < envp_cnt; i++) {
		print("%s, ", envp[i]);
	}

	print("\b\b}\n");
#endif
	struct task *current_task = CURRENT_TASK;

	struct vfs_node *vfs_node = vfs_search_absolute(NULL, path, true);
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		regs->rax = -1;
		return;
	}

	struct task *parent = current_task->parent;
	VECTOR_REMOVE_BY_VALUE(parent->children, current_task);
	VECTOR_REMOVE_BY_VALUE(parent->group->process_list, current_task);

	if(stat_has_access(vfs_node->stat, current_task->effective_uid,
		current_task->effective_gid, X_OK) == -1) {
		set_errno(EACCES);
		regs->rax = -1;
		return;
	}

	bool is_suid = vfs_node->stat->st_mode & S_ISUID ? true : false;
	bool is_sgid = vfs_node->stat->st_mode & S_ISGID ? true : false;

	struct task *task = sched_default_task(current_task->namespace);
	if(task == NULL) panic("");

	int ret = sched_load_program(task, path);
	if(ret == -1) {
		regs->rax = -1;
		return;
	}

	ret = sched_task_init(task, envp, argv);
	if(ret == -1) {
		regs->rax = -1;
		return;
	}

	waitq_trigger_calibrate(task->status_trigger, task, EVENT_PROCESS_STATUS);
	waitq_add(current_task->waitq, task->status_trigger);

	bitmap_dup(&current_task->fd_table->fd_bitmap, &task->fd_table->fd_bitmap);
	for(size_t i = 0; i < task->fd_table->fd_bitmap.size; i++) {
		if(BIT_TEST(task->fd_table->fd_bitmap.data, i)) {
			struct fd_handle *handle = fd_translate(i);
			if(handle->flags & O_CLOEXEC) {
				fd_close(i);
				continue;
			}

			hash_table_push(&task->fd_table->fd_list, &handle->fd_number, handle, sizeof(handle->fd_number));
		}
	}

	hash_table_delete(&task->namespace->process_list, &current_task->pid, sizeof(current_task->pid));
	hash_table_delete(&task->namespace->process_list, &task->pid, sizeof(task->pid));

	task->cwd = current_task->cwd;
	task->pid = current_task->pid;
	task->parent = current_task->parent;
	task->status_trigger = current_task->status_trigger;

	task->real_uid = current_task->real_uid;
	task->effective_uid = is_suid ? vfs_node->stat->st_uid : current_task->effective_uid;
	task->saved_uid = task->effective_uid;

	task->real_gid = current_task->real_gid;
	task->effective_gid = is_sgid ? vfs_node->stat->st_gid : current_task->effective_gid;
	task->saved_gid = task->effective_gid;

	task->group = current_task->group;
	task->session = current_task->session;

	task->umask = current_task->umask;
	task->has_execved = 1;

	for(size_t i = 0; i < SIGNAL_MAX; i++) {
		struct sigaction *task_act = &task->sigactions[i];
		struct sigaction *current_act = &current_task->sigactions[i];
		memset(task_act, 0, sizeof(struct sigaction));
		if(current_act->handler.sa_handler == SIG_IGN) {
			task_act->handler.sa_handler = SIG_IGN;
		} else {
			task_act->handler.sa_handler = SIG_DFL;
		}
	}

	task->signal_queue.sigmask = current_task->signal_queue.sigmask;
	task->signal_queue.sigpending = current_task->signal_queue.sigpending;
	memcpy(&task->signal_queue.queue, &current_task->signal_queue.queue, SIGNAL_MAX * sizeof(struct signal));

	VECTOR_PUSH(parent->children, task);
	VECTOR_PUSH(task->group->process_list, task);

	CORE_LOCAL->pid = -1;
	CORE_LOCAL->tid = -1;

	hash_table_push(&task->namespace->process_list, &task->pid, task, sizeof(task->pid));

	task->sched_status = TASK_WAITING;

	sched_yield();
}

void syscall_clone(struct registers *regs) {
	spinlock_irqsave(&sched_lock);

	void *function = (void*)regs->rdi;
	void *stack = (void*)regs->rsi;
	int flags = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] clone\n", CORE_LOCAL->pid);
#endif

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	struct task *task = alloc(sizeof(struct task));

	if((flags & CLONE_FILES) == CLONE_FILES) {
		spinlock_irqsave(&current_task->fd_table->fd_lock);

		spinrelease_irqsave(&current_task->fd_table->fd_lock);
	} else {
		spinlock_irqsave(&current_task->fd_table->fd_lock);

		for(size_t i = 0; i < current_task->fd_table->fd_list.capacity; i++) {
			struct fd_handle *handle = current_task->fd_table->fd_list.data[i];
			if(handle) {
				struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));
				*new_handle = *handle;
				file_get(new_handle->file_handle);
				hash_table_push(&task->fd_table->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));
			}
		}

		bitmap_dup(&current_task->fd_table->fd_bitmap, &task->fd_table->fd_bitmap);

		spinrelease_irqsave(&current_task->fd_table->fd_lock);
	}

	if((flags & CLONE_FS) == CLONE_FS) {
		task->cwd = current_task->cwd;
		task->umask = current_task->umask;
	}

	if((flags & CLONE_PARENT) == CLONE_PARENT) {
		task->parent = current_task->parent;
	} else {
		task->parent = current_task;
	}

	if((flags & CLONE_SIGHAND) == CLONE_SIGHAND) {
		task->sigactions = current_task->sigactions;
	} else {
		task->sigactions = alloc(sizeof(struct sigaction) * SIGNAL_MAX);
		memcpy(task->sigactions, current_task->sigactions, SIGNAL_MAX * sizeof(struct sigaction));
	}

	if((flags & CLONE_THREAD) == CLONE_THREAD) {
		
	}

	if((flags & CLONE_VM) == CLONE_VM) {
		task->page_table = current_task->page_table;
	} else {
		task->page_table = vmm_fork_page_table(current_task->page_table);
	}

	task->sched_status = TASK_WAITING;
	task->sched_status = TASK_WAITING;

	task->real_uid = current_task->real_uid;
	task->effective_uid = current_task->effective_uid;
	task->saved_uid = current_task->saved_uid;

	task->real_gid = current_task->real_gid;
	task->effective_gid = current_task->effective_gid;
	task->saved_gid = current_task->saved_gid;

	task->kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->kernel_stack.size = THREAD_KERNEL_STACK_SIZE;

	task->signal_kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->signal_kernel_stack.size = THREAD_KERNEL_STACK_SIZE;
}

void syscall_fork(struct registers *regs) {
	spinlock_irqsave(&sched_lock);

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] fork\n", CORE_LOCAL->pid);
#endif

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	task_lock(current_task);
	struct task *task = alloc(sizeof(struct task));

	task->fd_table = alloc(sizeof(struct fd_table));
	task->fd_table->fd_bitmap.resizable = true;

	task->namespace = current_task->namespace;

	task->pid = bitmap_alloc(&current_task->namespace->pid_bitmap);
	task->parent = current_task;
	task->sched_status = TASK_WAITING;
	task->page_table = vmm_fork_page_table(current_task->page_table);
	task->cwd = current_task->cwd;

	task->real_uid = current_task->real_uid;
	task->effective_uid = current_task->effective_uid;
	task->saved_uid = current_task->saved_uid;

	task->real_gid = current_task->real_gid;
	task->effective_gid = current_task->effective_gid;
	task->saved_gid = current_task->saved_gid;

	task->umask = current_task->umask;

	task->group = current_task->group;
	task->session = current_task->session;

	task->sigactions = alloc(sizeof(struct sigaction) * SIGNAL_MAX);
	memcpy(task->sigactions, current_task->sigactions, SIGNAL_MAX * sizeof(struct sigaction));

	task->waitq = alloc(sizeof(struct waitq));
	task->status_trigger = waitq_alloc(CURRENT_TASK->waitq, EVENT_PROCESS_STATUS);
	waitq_trigger_calibrate(task->status_trigger, task, EVENT_PROCESS_STATUS);

	spinlock_irqsave(&current_task->fd_table->fd_lock);

	for(size_t i = 0; i < current_task->fd_table->fd_list.capacity; i++) {
		struct fd_handle *handle = current_task->fd_table->fd_list.data[i];
		if(handle) {
			struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));
			*new_handle = *handle;
			file_get(new_handle->file_handle);
			hash_table_push(&task->fd_table->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));
		}
	}

	bitmap_dup(&current_task->fd_table->fd_bitmap, &task->fd_table->fd_bitmap);

	spinrelease_irqsave(&current_task->fd_table->fd_lock);

	task->regs = *regs;
	task->user_gs_base = CURRENT_TASK->user_gs_base;
	task->user_fs_base = CURRENT_TASK->user_fs_base;

	task->kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->kernel_stack.size = THREAD_KERNEL_STACK_SIZE;

	task->signal_kernel_stack.sp = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + THREAD_KERNEL_STACK_SIZE + HIGH_VMA;
	task->signal_kernel_stack.size = THREAD_KERNEL_STACK_SIZE;

	task->user_stack = CURRENT_TASK->user_stack;

	task->sched_status = TASK_WAITING;
	task->signal_queue.sigmask = CURRENT_TASK->signal_queue.sigmask;

	hash_table_push(&task->namespace->process_list, &task->pid, task, sizeof(task->pid));

	regs->rax = task->pid;
	task->regs.rax = 0;

	VECTOR_PUSH(current_task->children, task);

	task_unlock(current_task);
	spinrelease_irqsave(&sched_lock);
}

void syscall_getpid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getpid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CORE_LOCAL->pid;
}

void syscall_getppid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getppid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CURRENT_TASK->parent->pid;
}

void syscall_gettid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] gettid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CORE_LOCAL->tid;
}

void syscall_getuid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getuid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CURRENT_TASK->real_uid;
}

void syscall_geteuid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] geteuid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CURRENT_TASK->effective_uid;
}

void syscall_getgid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getgid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CURRENT_TASK->real_gid;
}

void syscall_getegid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getegid\n", CORE_LOCAL->pid);
#endif
	regs->rax = CURRENT_TASK->effective_gid;
}

void syscall_setuid(struct registers *regs) {
	uid_t uid = regs->rdi;
	struct task *current_task = CURRENT_TASK;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] setuid: uid {%x}\n", CORE_LOCAL->pid, uid);
#endif

	if(current_task->effective_uid == 0) {
		current_task->real_uid = uid;
		current_task->effective_uid = uid;
		current_task->saved_uid = uid;
		regs->rax = 0;
		return;
	}

	if(current_task->real_uid == uid || current_task->effective_uid == uid || current_task->saved_uid == uid) {
		current_task->effective_uid = uid;
		regs->rax = 0;
		return;
	}

	set_errno(EPERM);
	regs->rax = -1;
}

void syscall_seteuid(struct registers *regs) {
	uid_t euid = regs->rdi;
	struct task *current_task = CURRENT_TASK;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] seteuid: euid {%x}\n", CORE_LOCAL->pid, euid);
#endif

	if(current_task->real_uid == euid || current_task->effective_uid == euid || current_task->saved_uid == euid) {
		current_task->effective_uid = euid;
		regs->rax = 0;
		return;
	}

	set_errno(EPERM);
	regs->rax = -1;
}

void syscall_setgid(struct registers *regs) {
	gid_t gid = regs->rdi;
	struct task *current_task = CURRENT_TASK;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] setgid: gid {%x}\n", CORE_LOCAL->pid, gid);
#endif

	if(current_task->effective_uid == 0) {
		current_task->real_gid = gid;
		current_task->effective_gid = gid;
		current_task->saved_gid = gid;
		regs->rax = 0;
		return;
	}

	if(current_task->real_gid == gid || current_task->effective_gid == gid || current_task->saved_gid == gid) {
		current_task->effective_gid = gid;
		regs->rax = 0;
		return;
	}

	set_errno(EPERM);
	regs->rax = -1;
}

void syscall_setegid(struct registers *regs) {
	uid_t egid = regs->rdi;
	struct task *current_task = CURRENT_TASK;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] setegid: egid {%x}\n", CORE_LOCAL->pid, egid);
#endif

	if(current_task->real_gid == egid || current_task->effective_gid == egid || current_task->saved_gid == egid) {
		current_task->effective_gid = egid;
		regs->rax = 0;
		return;
	}

	set_errno(EPERM);
	regs->rax = -1;
}

void syscall_setpgid(struct registers *regs) {
	pid_t pid = regs->rdi == 0 ? CORE_LOCAL->pid : regs->rdi;
	pid_t pgid = regs->rsi == 0 ? CORE_LOCAL->pid : regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] setpgid: pid {%x}, pgid {%x}\n", CORE_LOCAL->pid, pid, pgid);
#endif

	struct task *task = sched_translate_pid(CORE_LOCAL->nid, pid);
	if(task == NULL) {
		set_errno(ESRCH);
		regs->rax = -1;
		return;
	}

	regs->rax = task_setpgid(task, pgid);
}

void syscall_getpgid(struct registers *regs) {
	pid_t pid = regs->rdi == 0 ? CORE_LOCAL->pid : regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getpgid: pid {%x}\n", CORE_LOCAL->pid, pid);
#endif

	struct task *task = sched_translate_pid(CORE_LOCAL->nid, pid);
	if(task == NULL) {
		set_errno(ESRCH);
		regs->rax = -1;
		return;
	}

	if(task->session != CURRENT_TASK->session) {
		set_errno(EPERM);
		regs->rax = -1;
		return;
	}

	regs->rax = task->group->pgid;
}

void syscall_setsid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] setsid\n", CORE_LOCAL->pid);
#endif

	struct task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		panic("");
	}

	regs->rax = task_create_session(current_task, false);
}

void syscall_getsid(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getsid\n", CORE_LOCAL->pid);
#endif

	regs->rax = CURRENT_TASK->session->sid;
}
