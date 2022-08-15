#include <sched/queue.h>
#include <sched/sched.h>
#include <errno.h>
#include <cpu.h>

int waitq_wait(struct waitq *waitq, int type) {
	struct task *task = CURRENT_TASK;

	spinlock_irqsave(&waitq->lock);

	if(waitq->status & type) {
		/*int ret;
		bsfl((waitq->status & type), &ret);
		spinrelease_irqsave(&waitq->lock);
		return ret;*/
		return waitq->status & type;
	}

	VECTOR_PUSH(waitq->tasks, task);

	spinrelease_irqsave(&waitq->lock);

	for(;;) {
		sched_dequeue(task);

		task->signal_queue.active = true;

		task->blocking = true;
		asm volatile ("sti");
		while(task->blocking);
		task->blocking = false;

		task->signal_queue.active = false;

		if(task->signal_release_block) {
			task->signal_release_block = false;
			set_errno(EINTR);
			return -1;
		}

		struct waitq_trigger *trigger = (void*)task->last_trigger;
		if(trigger == NULL) {
			continue;
		}

		if(type == EVENT_ANY) {
			return trigger->type;
		} else if((trigger->type & type)) {
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
	spinlock_irqsave(&waitq->lock);

	VECTOR_PUSH(waitq->triggers, trigger);

	trigger->waitq = waitq;
	trigger->refcnt++;

	spinrelease_irqsave(&waitq->lock);

	return 0;
}

int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger) {
	if(waitq == NULL || trigger == NULL) {
		return -1;
	}

	spinlock_irqsave(&waitq->lock);

	VECTOR_REMOVE_BY_VALUE(waitq->triggers, trigger);

	trigger->refcnt--;
	if(trigger->refcnt == 0) {
		free(trigger);
	}

	spinrelease_irqsave(&waitq->lock);

	return 0;
}

int waitq_wake(struct waitq_trigger *trigger) {
	if(trigger == NULL || trigger->waitq == NULL) {
		return -1;
	}

	struct waitq *waitq = trigger->waitq;

	spinlock_irqsave(&waitq->lock);

	trigger->fired = 1;

	waitq_obtain(waitq, trigger->type);

	for(size_t i = 0; i < waitq->tasks.length; i++) {
		struct task *task = waitq->tasks.data[i];

		task->last_trigger = trigger;
		task->blocking = false;

		sched_requeue(task);
	}

	VECTOR_CLEAR(waitq->tasks);

	spinrelease_irqsave(&waitq->lock);

	return 0;
}

int waitq_trigger_calibrate(struct waitq_trigger *trigger, struct task *task, int type) {
	if(trigger == NULL) {
		return -1;
	}

	spinlock_irqsave(&trigger->lock);

	trigger->agent_task = task;
	trigger->type = type;

	spinrelease_irqsave(&trigger->lock);

	return 0;
}

struct waitq_trigger *waitq_alloc(struct waitq *waitq, int type) {
	struct waitq_trigger *trigger = alloc(sizeof(struct waitq_trigger));

	trigger->waitq = waitq;
	trigger->type = type;
	trigger->refcnt = 0;

	return trigger;
}
