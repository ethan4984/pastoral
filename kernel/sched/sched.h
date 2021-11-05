#pragma once

#include <fs/fd.h>
#include <vector.h>
#include <types.h>
#include <mm/vmm.h>
#include <cpu.h>
#include <bitmap.h>

struct sched_thread {
	tid_t tid;
	pid_t pid; 

	size_t status;
	size_t idle_cnt;
	size_t user_stack;
	size_t kernel_stack;
	size_t user_gs_base;
	size_t kernel_stack_size;
	size_t user_stack_size;
	size_t errno;

	struct registers regs;
}; 

struct sched_task {
	VECTOR(struct fd_handle*) fd_list;
	struct bitmap fd_bitmap;

	VECTOR(struct sched_thread*) thread_list;
	struct bitmap thread_bitmap;

	pid_t pid;
	pid_t ppid;

	size_t idle_cnt;
	size_t status;

	struct page_table *page_table;
};

struct sched_task *translate_pid(pid_t pid);
struct sched_thread *translate_tid(pid_t pid, tid_t tid);

#define CURRENT_TASK ({ \
	translate_pid(CORE_LOCAL->pid); \
})

#define CURRENT_THREAD ({ \
	translate_tid(CORE_LOCAL->pid, CORE_LOCAL->tid); \
})
