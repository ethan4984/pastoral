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

struct sched_thread {
	tid_t tid;
	pid_t pid;

	size_t sched_status;
	size_t idle_cnt;
	size_t user_stack;
	size_t kernel_stack;
	size_t user_gs_base;
	size_t user_fs_base;
	size_t kernel_stack_size;
	size_t user_stack_size;
	size_t errno;

	struct signal_queue signal_queue;

	struct registers regs;
};

struct process_group;
struct session;

struct sched_task {
	char fd_lock;
	struct hash_table fd_list;
	struct bitmap fd_bitmap;

	char tid_lock;
	struct hash_table thread_list;
	struct bitmap tid_bitmap;

	struct waitq *waitq;
	volatile int waiting;

	struct waitq_trigger *exit_trigger;
	struct waitq_trigger *last_trigger;

	struct vfs_node *cwd;

	char lock;
	pid_t pid;
	pid_t ppid;
	struct process_group *group;
	struct session *session;

	int has_execved;

	size_t idle_cnt;
	int sched_status;
	int exit_status;

	uid_t real_uid;
	uid_t effective_uid;
	uid_t saved_uid;

	gid_t real_gid;
	gid_t effective_gid;
	gid_t saved_gid;

	mode_t umask;

	char sig_lock;
	struct sigaction sigactions[SIGNAL_MAX];

	VECTOR(struct sched_task*) children;

	struct page_table *page_table;
};

struct process_group {
	char lock;

	pid_t pgid;
	pid_t pid_leader;

	struct sched_task *leader;
	struct session *session;

	VECTOR(struct sched_task*) process_list;
};

struct session {
	char lock;

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

struct sched_task *sched_translate_pid(pid_t pid);
struct sched_thread *sched_translate_tid(pid_t pid, tid_t tid);
struct sched_task *sched_default_task();
struct sched_thread *sched_default_thread(struct sched_task *task);
struct sched_task *sched_task_exec(const char *path, uint16_t cs, struct sched_arguments *arguments, int status);
struct sched_thread *sched_thread_exec(struct sched_task *task, uint64_t rip, uint16_t cs, struct aux *aux, struct sched_arguments *arguments);

void reschedule(struct registers *regs, void *ptr);
void sched_dequeue(struct sched_task *task, struct sched_thread *thread);
void sched_dequeue_and_yield(struct sched_task *task, struct sched_thread *thread);
void sched_requeue(struct sched_task *task, struct sched_thread *thread);
void sched_requeue_and_yield(struct sched_task *task, struct sched_thread *thread);
void sched_yield();
void task_terminate(struct sched_task *task, int status);
int task_create_session(struct sched_task *task, bool force);

extern char sched_lock;

#define CURRENT_TASK ({ \
	sched_translate_pid(CORE_LOCAL->pid); \
})

#define CURRENT_THREAD ({ \
	sched_translate_tid(CORE_LOCAL->pid, CORE_LOCAL->tid); \
})

#define TASK_RUNNING 0
#define TASK_WAITING 1
#define TASK_YIELD 2

#define THREAD_KERNEL_STACK_SIZE 0x4000
#define THREAD_USER_STACK_SIZE 0x10000

#define TASK_MAX_PRIORITY ~(0ull)
#define TASK_MIN_PRIORITY ~(0)

static inline void session_lock(struct session *session) {
	spinlock(&session->lock);
}

static inline void session_unlock(struct session *session) {
	spinrelease(&session->lock);
}

static inline void process_group_lock(struct process_group *group) {
	spinlock(&group->lock);
}

static inline void process_group_unlock(struct process_group *group) {
	spinrelease(&group->lock);
}

static inline void task_lock(struct sched_task *task) {
	spinlock(&task->lock);
}

static inline void task_unlock(struct sched_task *task) {
	spinrelease(&task->lock);
}


#define WEXITSTATUS(x) ((x) & 0xff)
#define WIFCONTINUED(x) ((x) & 0x100)
#define WIFEXITED(x) ((x) & 0x200)
#define WIFSIGNALED(x) ((x) & 0x400)
#define WIFSTOPPED(x) ((x) & 0x800)
#define WSTOPSIG(x) (((x) & 0xff0000) >> 16)
#define WTERMSIG(x) (((x) & 0xff000000) >> 24)

#define WEXITED_CONSTRUCT(status) ((status & 0xff) | 0x200)
#define WSIGNALED_CONSTRUCT(status) ((((status & 0xff) << 16) | 0x400))
