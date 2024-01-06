#pragma once

#include <types.h>
#include <vector.h>
#include <lock.h>

struct task;
struct waitq;

struct waitq_trigger {
	struct task *task;

	VECTOR(struct waitq*) queues;
	int fired;

	int refcnt;
	struct spinlock lock;
};

struct waitq {
	VECTOR(struct task*) tasks;

	struct timespec timespec;
	struct waitq_trigger *timer_trigger;

	struct spinlock lock;
};

#define EVENT_DEFAULT_TRIGGER(WAITQ) ({ \
	struct waitq_trigger *_trigger = alloc(sizeof(struct waitq_trigger)); \
	waitq_add(WAITQ, _trigger); \
	_trigger; \
})

int waitq_block(struct waitq *waitq, struct waitq_trigger **waking_object);
int waitq_arise(struct waitq_trigger *waitq, struct task *waking_task);
int waitq_flush_trigger(struct waitq_trigger *trigger);
int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger);
int waitq_set_timer(struct waitq *waitq, const struct timespec *timespec);
