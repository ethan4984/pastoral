#pragma once

#include <fs/fd.h>
#include <vector.h>
#include <types.h>
#include <mm/vmm.h>
#include <cpu.h>
#include <bitmap.h>
#include <hash.h>
#include <elf.h>
#include <sched/signal.h>
#include <drivers/tty/tty.h>
#include <sched/signal.h>
#include <sched/program.h>
#include <sched/futex.h>
#include <lock.h>

struct task;
struct process_group;
struct session;

struct pid_namespace {
	nid_t nid;
	struct hash_table process_list;
	struct bitmap pid_bitmap;
};

struct task_id {
	nid_t nid;
	tid_t tid;
	pid_t pid;
}; 

struct task {
	struct spinlock lock;

	struct pid_namespace *namespace;
	struct task_id id;

	struct task *parent;
	struct process_group *group;
	struct session *session;

	int has_execved;

	size_t idle_cnt;
	int sched_status;
	int process_status;

	size_t user_gs_base;
	size_t user_fs_base;

	struct stack signal_user_stack;
	struct stack signal_kernel_stack;

	struct stack kernel_stack;
	struct stack user_stack;

	size_t errno;

	struct waitq *waitq;
	struct waitq_trigger *status_trigger;
	struct waitq_trigger *last_trigger;

	bool blocking;
	bool signal_release_block;

	struct signal_queue signal_queue;

	struct registers regs;
	struct ucontext signal_context;

	struct fd_table *fd_table;
	struct vfs_node **cwd;

	uid_t real_uid;
	uid_t effective_uid;
	uid_t saved_uid;

	gid_t real_gid;
	gid_t effective_gid;
	gid_t saved_gid;

	mode_t *umask;

	struct spinlock sig_lock;
	struct sigaction *sigactions;
	bool dispatch_ready;

	VECTOR(struct task*) children;
	VECTOR(struct task*) zombies;

	struct pid_namespace *thread_group;

	struct program program;
	struct page_table *page_table;
};

struct process_group {
	struct spinlock lock;

	pid_t pgid;
	pid_t pid_leader;

	struct task *leader;
	struct session *session;

	VECTOR(struct task*) process_list;
};

struct session {
	struct spinlock lock;

	pid_t sid;
	pid_t pgid_leader;

	struct hash_table group_list;

	struct tty *tty;
};

struct sched_arguments {
	int envp_cnt;
	int argv_cnt;

	char **argv;
	char **envp;
};

struct pid_namespace *sched_default_namespace();
struct task *sched_translate_pid(nid_t nid, pid_t pid, tid_t tid);
int sched_default_task(struct task *task, struct pid_namespace *namespace, int queue);
int sched_task_init(struct task *task, char **envp, char **argv);
int sched_load_program(struct task *task, const char *path);

void reschedule(struct registers *regs, void *ptr);
void sched_dequeue(struct task *task);
void sched_requeue(struct task *task);
void sched_yield();
void task_terminate(struct task *task, int status);
void task_stop(struct task *task, int sig);
void task_continue(struct task *task);
int task_create_session(struct task *task, bool force);

extern struct spinlock sched_lock;

#define CURRENT_TASK ({ \
	struct task *ret = NULL; \
	if(CORE_LOCAL) { \
		ret = sched_translate_pid(CORE_LOCAL->nid, CORE_LOCAL->pid, CORE_LOCAL->tid); \
	} \
	ret; \
})

#define SIGPENDING ({ \
	CURRENT_TASK->signal_queue.sigpending; \
})

#define TASK_RUNNING 0
#define TASK_WAITING 1
#define TASK_YIELD 2

#define THREAD_KERNEL_STACK_SIZE 0x4000
#define THREAD_USER_STACK_SIZE 0x100000

#define TASK_MAX_PRIORITY ~(0ull)
#define TASK_MIN_PRIORITY ~(0)

static inline void session_lock(struct session *session) {
	spinlock_irqsave(&session->lock);
}

static inline void session_unlock(struct session *session) {
	spinrelease_irqsave(&session->lock);
}

static inline void process_group_lock(struct process_group *group) {
	spinlock_irqsave(&group->lock);
}

static inline void process_group_unlock(struct process_group *group) {
	spinrelease_irqsave(&group->lock);
}

static inline void task_lock(struct task *task) {
	spinlock_irqsave(&task->lock);
}

static inline void task_unlock(struct task *task) {
	spinrelease_irqsave(&task->lock);
}

#define WEXITSTATUS(x) (((x) & 0xff00) >> 8)
#define WTERMSIG(x) ((x) & 0x7f)
#define WSTOPSIG(x) WEXITSTATUS(x)
#define WIFEXITED(x) (WTERMSIG(x) == 0)
#define WIFSIGNALED(x) (((signed char)(((x) & 0x7f) + 1) >> 1) > 0)
#define WIFSTOPPED(x) (((x) & 0xff) == 0x7f)
#define WIFCONTINUED(x) ((x) == 0xffff)
#define WCOREDUMP(x) ((x) & WCOREFLAG)

#define WSTATUS_CONSTRUCT(x) ((x) << 8)
#define WEXITED_CONSTRUCT(x) (WSTATUS_CONSTRUCT(x))
#define WSIGNALED_CONSTRUCT(x) ((x) & 0x7f)
#define WSTOPPED_CONSTRUCT(x) (0x7f)
#define WCONTINUED_CONSTRUCT 0xffff

struct clone_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
	uint64_t set_tid;
	uint64_t set_tid_size;
	uint64_t cgroup;
};

#define CLONE_VM 0x00000100
#define CLONE_FS 0x00000200
#define CLONE_FILES 0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_PTRACE 0x00002000
#define CLONE_VFORK 0x00004000
#define CLONE_PARENT 0x00008000
#define CLONE_THREAD 0x00010000
#define CLONE_NEWNS 0x00020000
#define CLONE_SYSVSEM 0x00040000
#define CLONE_SETTLS 0x00080000
#define CLONE_PARENT_SETTID 0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_DETACHED 0x00400000
#define CLONE_UNTRACED 0x00800000
#define CLONE_CHILD_SETTID 0x01000000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000
#define CLONE_IO 0x80000000
