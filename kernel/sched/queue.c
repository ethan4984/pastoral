#include <sched/queue.h>
#include <sched/sched.h>
#include <cpu.h>

int waitq_wait(struct waitq *waitq, int type) {
	struct sched_task *task = CURRENT_TASK;
	struct sched_thread *thread = CURRENT_THREAD;

	spinlock_irqdef(&waitq->lock);

	if((waitq->status & type) == type) {
		spinrelease_irqdef(&waitq->lock);
		return type;
	}

	VECTOR_PUSH(waitq->threads, thread);

	spinrelease_irqdef(&waitq->lock);

	for(;;) {
		sched_dequeue(task, thread);

		task->waiting = 1;

		asm volatile ("sti");

		while(task->waiting);
		task->waiting = 0;

		struct waitq_trigger *trigger = (void*)task->last_trigger;
		if(trigger == NULL) {
			continue;
		}

		if(type == EVENT_ANY) {
			return trigger->type;
		} else if((trigger->type & type) == type) {
			return trigger->type;
		}
	}

	return -1;
}

int waitq_set_timer(struct waitq *waitq, struct timespec timespec) {
	struct waitq_trigger *timer_trigger = waitq_alloc(waitq, EVENT_TIMER);

	waitq->timespec = timespec;
	waitq->timer_trigger = timer_trigger;

	struct timer *timer = alloc(sizeof(struct timer));
	timer->timespec = timespec;

	waitq_add(waitq, timer_trigger);

	VECTOR_PUSH(timer->triggers, (void*)timer_trigger);
	VECTOR_PUSH(timer_list, timer);

	return 0;
}

int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger) {
	spinlock_irqdef(&waitq->lock);

	VECTOR_PUSH(waitq->triggers, trigger);

	trigger->waitq = waitq;
	trigger->refcnt++;

	spinrelease_irqdef(&waitq->lock);

	return 0;
}

int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger) {
	if(waitq == NULL || trigger == NULL) {
		return -1;
	}

	spinlock_irqdef(&waitq->lock);

	VECTOR_REMOVE_BY_VALUE(waitq->triggers, trigger);

	trigger->refcnt--;
	if(trigger->refcnt == 0) {
		free(trigger);
	}

	spinrelease_irqdef(&waitq->lock);

	return 0;
}

int waitq_wake(struct waitq_trigger *trigger) {
	if(trigger == NULL || trigger->waitq == NULL) {
		return -1;
	}

	struct waitq *waitq = trigger->waitq;

	spinlock_irqdef(&waitq->lock);

	trigger->fired = 1;

	waitq_obtain(waitq, trigger->type);

	for(size_t i = 0; i < waitq->threads.length; i++) {
		struct sched_thread *thread = waitq->threads.data[i];
		struct sched_task *task = sched_translate_pid(thread->pid);

		task->last_trigger = trigger;

		sched_requeue(task, thread);
	}

	VECTOR_CLEAR(waitq->threads);

	spinrelease_irqdef(&waitq->lock);

	return 0;
}

int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct sched_task *task, struct sched_thread *thread, int type) {
	if(trigger == NULL) {
		return -1;
	}

	spinlock_irqdef(&trigger->lock);

	trigger->agent_task = task;
	trigger->agent_thread = thread;
	trigger->type = type;

	spinrelease_irqdef(&trigger->lock);

	return 0;
}

struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type) {
	struct waitq_trigger *trigger = alloc(sizeof(struct waitq_trigger));

	trigger->waitq = waitq;
	trigger->type = type;
	trigger->refcnt = 0;

	return trigger;
}
