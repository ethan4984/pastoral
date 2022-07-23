#include <sched/queue.h>
#include <sched/sched.h>
#include <cpu.h>

int waitq_wait(struct waitq *waitq, int type) {
	struct sched_task *task = CURRENT_TASK;
	struct sched_thread *thread = CURRENT_THREAD;

	spinlock(&waitq->lock);

	if(waitq->pending) {
		struct waitq_trigger *trigger = (void*)task->last_trigger;
		if(trigger == NULL) {
			waitq->pending--;
			spinrelease(&waitq->lock);
			return -1;
		}

		waitq->pending--;
		spinrelease(&waitq->lock);

		return trigger->type; 
	}

	spinrelease(&waitq->lock);

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

		if(trigger->type == type) {
			return trigger->type;
		}
	}

	return -1;
}

int waitq_set_timer(struct waitq *waitq, struct timespec timespec) {
	spinlock(&waitq->lock);

	struct waitq_trigger *timer_trigger = waitq_alloc(waitq, EVENT_TIMER);

	waitq->timespec = timespec;
	waitq->timer_trigger = timer_trigger;

	struct timer *timer = alloc(sizeof(struct timer));
	timer->timespec = timespec;

	waitq_add(waitq, timer_trigger);

	VECTOR_PUSH(timer->triggers, (void*)timer_trigger);
	VECTOR_PUSH(timer_list, timer);

	spinrelease(&waitq->lock);

	return 0;
}

int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger) {
	spinlock(&waitq->lock);

	VECTOR_PUSH(waitq->triggers, trigger);

	trigger->waitq = waitq;
	trigger->refcnt++;

	spinrelease(&waitq->lock);

	return 0;
}

int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger) {
	spinlock(&waitq->lock);

	VECTOR_REMOVE_BY_VALUE(waitq->triggers, trigger);

	trigger->refcnt--;
	if(trigger->refcnt == 0) {
		free(trigger);
	}

	spinrelease(&waitq->lock);

	return 0;
}

int waitq_wake(struct waitq_trigger *trigger) {
	if(trigger == NULL || trigger->waitq == NULL) {
		return -1; 
	}

	struct waitq *waitq = trigger->waitq;

	spinlock(&waitq->lock);

	waitq->pending++;
	waitq->task->last_trigger = (void*)trigger;
	sched_requeue(waitq->task, waitq->thread);

	spinrelease(&waitq->lock);

	return 0;
}

int waitq_calibrate(struct waitq *waitq, struct sched_task *task, struct sched_thread *thread) {
	spinlock(&waitq->lock);

	waitq->task = task;
	waitq->thread = thread;

	spinrelease(&waitq->lock);

	return 0;
}

int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct sched_task *task, struct sched_thread *thread, int type) {
	spinlock(&trigger->lock);

	trigger->agent_task = task;
	trigger->agent_thread = thread;
	trigger->type = type;

	spinrelease(&trigger->lock);

	return 0;
}

int waitq_init(struct waitq *waitq) {
	spinlock(&waitq->lock);

	waitq->task = CURRENT_TASK;
	waitq->thread = CURRENT_THREAD;

	spinrelease(&waitq->lock);

	return 0;
}

struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type) {
	struct waitq_trigger *trigger = alloc(sizeof(struct waitq_trigger));

	trigger->waitq = waitq;
	trigger->type = type;
	trigger->refcnt = 0;

	return trigger;
}
