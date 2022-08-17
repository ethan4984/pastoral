#pragma once

#include <types.h>
#include <vector.h>
#include <lock.h>

#define EVENT_ANY (1 << 0)
#define EVENT_READ (1 << 1)
#define EVENT_WRITE (1 << 2)
#define EVENT_TIMER (1 << 3)
#define EVENT_SIGNAL (1 << 4)
#define EVENT_COMMAND (1 << 5)
#define EVENT_POLLIN (1 << 6)
#define EVENT_POLLOUT (1 << 7)
#define EVENT_SOCKET (1 << 8)
#define EVENT_PROCESS_STATUS (1 << 9)
#define EVENT_LOCK (1 << 10)

struct task;
struct waitq;

struct waitq_trigger {
	struct task *agent_task;

	struct waitq *waitq;
	int type;
	int fired;

	int refcnt;
	struct spinlock lock;
};

struct waitq {
	struct task *task;

	VECTOR(struct task*) tasks;
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
int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct task *task, int type);
int waitq_wake(struct waitq_trigger *trigger);
struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type);

static inline void waitq_release(struct waitq *waitq, int type) {
	waitq->status &= ~(type);
}

static inline void waitq_obtain(struct waitq *waitq, int type) {
	waitq->status |= type;
}
