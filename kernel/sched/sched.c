#include <sched/sched.h>
#include <vector.h>
#include <cpu.h>

static VECTOR(struct sched_task*) task_list;

static char sched_lock;

struct sched_task *translate_pid(pid_t pid) {
	spinlock(&sched_lock);

	for(size_t i = 0; i < task_list.element_cnt; i++) {
		if(task_list.elements[i]->pid == pid) {
			spinrelease(&sched_lock);
			return task_list.elements[i];
		}
	}

	spinrelease(&sched_lock);

	return NULL;
}

struct sched_thread *translate_tid(pid_t pid, tid_t tid) {
	struct sched_task *task = translate_pid(pid);
	if(task == NULL) {
		return NULL;
	}
	
	spinlock(&sched_lock);

	for(size_t i = 0; i < task_list.element_cnt; i++) {
		if(task->thread_list.elements[i]->tid == tid) {
			spinrelease(&sched_lock);
			return task->thread_list.elements[i];
		}
	}

	spinrelease(&sched_lock);

	return NULL;
}
