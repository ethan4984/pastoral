#pragma once

#include <fs/fd.h>
#include <vector.h>
#include <types.h>
#include <mm/vmm.h>
#include <cpu.h>
#include <bitmap.h>
#include <hash.h>
#include <elf.h>

struct sched_thread {
	tid_t tid;
	pid_t pid; 

	size_t status;
	size_t idle_cnt;
	size_t user_stack;
	size_t kernel_stack;
	size_t user_gs_base;
	size_t user_fs_base;
	size_t kernel_stack_size;
	size_t user_stack_size;
	size_t errno;

	struct vfs_node *cwd;

	struct registers regs;
}; 

struct sched_task {
	struct hash_table fd_list;
	struct bitmap fd_bitmap;

	struct hash_table thread_list;
	struct bitmap tid_bitmap;

	pid_t pid;
	pid_t ppid;

	size_t idle_cnt;
	size_t status;

	struct page_table *page_table;
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
struct sched_task *sched_task_exec(const char *path, uint16_t cs, struct sched_arguments *arguments);
struct sched_thread *sched_thread_exec(struct sched_task *task, uint64_t rip, uint16_t cs, struct aux *aux, struct sched_arguments *arguments);

void reschedule(struct registers *regs, void *ptr);

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

#define THREAD_KERNEL_STACK_SIZE 0x2000
#define THREAD_USER_STACK_SIZE 0x8000
