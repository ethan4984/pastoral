#pragma once

#include <types.h>
#include <vector.h>
#include <lock.h>

#define EVENT_ANY (1 << 0)
#define EVENT_EXIT (1 << 1)
#define EVENT_READ (1 << 2)
#define EVENT_WRITE (1 << 3)
#define EVENT_TIMER (1 << 4)
#define EVENT_SIGNAL (1 << 5)
#define EVENT_COMMAND (1 << 6)
#define EVENT_POLLIN (1 << 7)
#define EVENT_POLLOUT (1 << 8)
#define EVENT_SOCKET (1 << 9)
#define EVENT_JOB_STOP (1 << 10)
#define EVENT_JOB_CONTINUE (1 << 11)

struct sched_task;
struct sched_thread;
struct waitq;

struct waitq_trigger {
	struct sched_task *agent_task;
	struct sched_thread *agent_thread;

	struct waitq *waitq;
	int type;
	int fired;

	int refcnt;
	struct spinlock lock;
};

struct waitq {
	struct sched_task *task;
	struct sched_thread *thread;

	VECTOR(struct sched_thread *) threads;
	VECTOR(struct waitq_trigger*) triggers;

	struct timespec timespec;
	struct waitq_trigger *timer_trigger;

	int status;

	struct spinlock lock;
};

int waitq_wait(struct waitq *waitq, int type);
int waitq_set_timer(struct waitq *waitq, struct timespec timespec);
int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct sched_task *task, struct sched_thread *thread, int type);
int waitq_wake(struct waitq_trigger *trigger);
struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type);

static inline void waitq_release(struct waitq *waitq, int type) {
	waitq->status &= ~(type);
}

static inline void waitq_obtain(struct waitq *waitq, int type) {
	waitq->status |= type;
}
