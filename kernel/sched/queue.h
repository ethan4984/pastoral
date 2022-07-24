#pragma once

#include <types.h>
#include <vector.h>

#define EVENT_ANY (0 << 0)
#define EVENT_EXIT (1 << 0)
#define EVENT_READ (1 << 1)
#define EVENT_WRITE (1 << 2)
#define EVENT_TIMER (1 << 3)
#define EVENT_SIGNAL (1 << 4)
#define EVENT_COMMAND (1 << 5)
#define EVENT_POLLIN (1 << 6)
#define EVENT_POLLOUT (1 << 7)

struct sched_task;
struct sched_thread;
struct waitq;

struct waitq_trigger {
	struct sched_task *agent_task;
	struct sched_thread *agent_thread;

	struct waitq *waitq;
	int type;

	int refcnt;
	char lock;
};

struct waitq {
	struct sched_task *task;
	struct sched_thread *thread;

	VECTOR(struct waitq_trigger*) triggers;

	struct timespec timespec;
	struct waitq_trigger *timer_trigger;

	int pending;
	char lock;
};

int waitq_init(struct waitq *wait);
int waitq_wait(struct waitq *waitq, int type);
int waitq_set_timer(struct waitq *waitq, struct timespec timespec);
int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_calibrate(struct waitq *waitq, struct sched_task *task, struct sched_thread *thread);
int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct sched_task *task, struct sched_thread *thread, int type);
int waitq_wake(struct waitq_trigger *trigger);

struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type);
