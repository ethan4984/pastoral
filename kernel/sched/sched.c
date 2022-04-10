#include <sched/sched.h>
#include <int/apic.h>
#include <vector.h>
#include <cpu.h>
#include <mm/pmm.h>
#include <string.h>
#include <debug.h>

static struct hash_table task_list;

struct bitmap pid_bitmap = {
    .data = NULL,
    .size = 0,
    .resizable = true
};

char sched_lock;

// does not lock **remember** 
struct sched_task *sched_translate_pid(pid_t pid) {
    return hash_table_search(&task_list, &pid, sizeof(pid));
}

// does not lock **remember** 
struct sched_thread *sched_translate_tid(pid_t pid, tid_t tid) {
	struct sched_task *task = sched_translate_pid(pid);
	if(task == NULL) {
		return NULL;
	}

    return hash_table_search(&task->thread_list, &tid, sizeof(tid));
}

struct sched_thread *find_next_thread(struct sched_task *task) {
    struct sched_thread *ret = NULL;

    for(size_t i = 0, cnt = 0; i < task->thread_list.capacity; i++) {
        if(task->thread_list.data[i] == NULL) {
            continue;
        }

        struct sched_thread *next_thread = task->thread_list.data[i];
        next_thread->idle_cnt++;

        if(next_thread->status == TASK_WAITING && cnt < next_thread->idle_cnt) {
            cnt = next_thread->idle_cnt;
            ret = next_thread;
        }
    }

    return ret;
}

struct sched_task *find_next_task() {
    struct sched_task *ret = NULL;

    for(size_t i = 0, cnt = 0; i < task_list.capacity; i++) {
        if(task_list.data[i] == NULL) {
            continue;
        }

        struct sched_task *next_task = task_list.data[i];
        next_task->idle_cnt++;

        if(next_task->status == TASK_WAITING && cnt < next_task->idle_cnt) {
            cnt = next_task->idle_cnt;
            ret = next_task;
        }
    }

    return ret;
}

#define EXIT_RESCHEDULE() ({ \
    if(regs->cs & 0x3) { \
        swapgs(); \
    } \
    xapic_write(XAPIC_EOI_OFF, 0); \
    spinrelease(&sched_lock); \
    return; \
})

void reschedule(struct registers *regs, void*) {
    if(__atomic_test_and_set(&sched_lock, __ATOMIC_ACQUIRE)) {
        return;
    }

    if(regs->cs & 0x3) {
        swapgs();
    }

    struct sched_task *next_task = find_next_task();
    if(next_task == NULL) {
        EXIT_RESCHEDULE();
    }

    struct sched_thread *next_thread = find_next_thread(next_task);
    if(next_thread == NULL) {
        EXIT_RESCHEDULE();
    }

    if(CORE_LOCAL->tid != -1 && CORE_LOCAL->pid != -1) {
        struct sched_task *last_task = sched_translate_pid(CORE_LOCAL->pid);         
        if(last_task == NULL) {
            EXIT_RESCHEDULE();
        }

        struct sched_thread *last_thread = sched_translate_tid(CORE_LOCAL->pid, CORE_LOCAL->tid);
        if(last_thread == NULL) {
            EXIT_RESCHEDULE();
        }

        last_thread->status = TASK_WAITING;
        last_task->status = TASK_WAITING;

        last_thread->errno = CORE_LOCAL->errno;
        last_thread->regs = *regs;
        last_thread->user_fs_base = get_user_fs();
        last_thread->user_gs_base = get_user_gs();
        last_thread->user_stack = CORE_LOCAL->user_stack;
    }

    CORE_LOCAL->pid = next_task->pid;
    CORE_LOCAL->tid = next_thread->tid;
    CORE_LOCAL->errno = next_thread->errno;
    CORE_LOCAL->kernel_stack = next_thread->kernel_stack;
    CORE_LOCAL->user_stack = next_thread->user_stack;

    CORE_LOCAL->page_table = next_task->page_table;
    vmm_init_page_table(CORE_LOCAL->page_table);

    next_thread->idle_cnt = 0;
    next_task->idle_cnt = 0;
    next_task->status = TASK_RUNNING;
    next_thread->status = TASK_RUNNING;

    set_user_fs(next_thread->user_fs_base);
    set_user_gs(next_thread->user_gs_base);

    if(next_thread->regs.cs & 0x3) {
        swapgs();
    }

    xapic_write(XAPIC_EOI_OFF, 0);
    spinrelease(&sched_lock);

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
        :: "r" (&next_thread->regs)
    );
}

struct sched_task *sched_default_task() {
    struct sched_task *task = alloc(sizeof(struct sched_task));

    task->pid = bitmap_alloc(&pid_bitmap);
    task->status = TASK_YIELD;
    task->fd_bitmap.resizable = true;

    task->tid_bitmap = (struct bitmap) {
        .data = NULL,
        .size = 0,
        .resizable = true
    };

    if(CURRENT_TASK != NULL) {
        task->ppid = CURRENT_TASK->pid;
    } else {
        task->ppid = -1;
    }

    hash_table_push(&task_list, &task->pid, task, sizeof(task->pid));

    return task;
}

struct sched_thread *sched_default_thread(struct sched_task *task) {
    struct sched_thread *thread = alloc(sizeof(struct sched_thread));

    thread->pid = task->pid;
    thread->tid = bitmap_alloc(&task->tid_bitmap);
    thread->status = TASK_YIELD;

    thread->kernel_stack = pmm_alloc(DIV_ROUNDUP(THREAD_KERNEL_STACK_SIZE, PAGE_SIZE), 1) + HIGH_VMA;
    thread->kernel_stack_size = THREAD_KERNEL_STACK_SIZE;

    hash_table_push(&task->thread_list, &thread->tid, thread, sizeof(thread->tid));

    return thread;
}
