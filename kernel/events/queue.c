#include <events/queue.h>
#include <sched/sched.h>
#include <errno.h>
#include <debug.h>
#include <cpu.h>

/*
 * usage:
 *	for(a; b; c) {
 *		waitq_add(waitq,. possible_trigger);
 *	}
 *														  
 *	struct task *waking_task;
 *	uint64_t ret;
 *														  
 *	for(;;) {
 *		if(condition) {
 *			break;
 *		}
 *														  
 *		struct waitq_trigger *waking_trigger;
 *		ret = waitq_block(waitq, &waking_trigger);
 *		if(ret == -1) { 
 *			goto finish;
 *		}
 *	}
 *														  
 *	for(a; b; c) {
 *		waitq_remove(waitq, possible_trigger);
 *	}
 */

int waitq_block(struct waitq *waitq, struct waitq_trigger **waking_object) {
	struct task *task = CURRENT_TASK;

	spinlock_irqsave(&waitq->lock);
	VECTOR_PUSH(waitq->tasks, task);
	spinrelease_irqsave(&waitq->lock);

	//print("queue: blocking on thread %x:%x\n", CORE_LOCAL->pid, CORE_LOCAL->tid);

	task->signal_queue.active = true;
	task->blocking = true;

	sched_dequeue(task);
	while(task->blocking) sched_initiate_resched();

	task->signal_queue.active = false; 

	if(task->signal_release_block) {
		task->signal_release_block = false;
		set_errno(EINTR);
		return -1;
	}

	//print("queue: waking on thread %x:%x\n", CORE_LOCAL->pid, CORE_LOCAL->tid);

	if(waking_object) {
		*waking_object = task->last_trigger;
	}

	return 0;
}

int waitq_arise(struct waitq_trigger *trigger, struct task *waking_task) {
	if(trigger == NULL) {
		return -1;
	}

	/*print("queue: attempting to wake queues:\n");

	for(int i = 0; i < trigger->queues.length; i++) {
		print("\t[queue] %d:\n", i);

		struct waitq *queue = trigger->queues.data[i];
		if(queue == NULL) {
			continue;
		}

		for(int j = 0; j < queue->tasks.length; j++) {
			struct task *task = queue->tasks.data[j];
			if(task == NULL) {
				continue;
			}

			print("\t\t[waking] %x:%x\n", task->id.pid, task->id.tid);
		}
	}*/

	trigger->task = waking_task;

	spinlock_irqsave(&trigger->lock);
	
	for(size_t i = 0; i < trigger->queues.length; i++) {
		struct waitq *waitq = trigger->queues.data[i];

		if(waitq == NULL) {
			continue;
		}

		spinlock_irqsave(&waitq->lock);

		for(size_t j = 0; j < waitq->tasks.length; j++) {
			struct task *task = waitq->tasks.data[j];
			if(task == NULL) {
				print("TASK NULL\n");
				continue;
			}

			task->last_trigger = trigger;
			task->blocking = false;

			sched_requeue(task);
		}

		VECTOR_CLEAR(waitq->tasks);

		spinrelease_irqsave(&waitq->lock);
	}

	spinrelease_irqsave(&trigger->lock);

	return 0;
}

int waitq_add(struct waitq *waitq, struct waitq_trigger *trigger) {
	if(waitq == NULL || trigger == NULL) {
		return -1;
	}

	spinlock_irqsave(&trigger->lock);

	VECTOR_PUSH(trigger->queues, waitq);
	trigger->refcnt++;

	spinrelease_irqsave(&trigger->lock);

	return 0;
}

int waitq_flush_trigger(struct waitq_trigger *trigger) {
	spinlock_irqsave(&trigger->lock);

	VECTOR_CLEAR(trigger->queues);
	trigger->refcnt = 0;

	spinrelease_irqsave(&trigger->lock);

	return 0;
}

int waitq_set_timer(struct waitq *waitq, const struct timespec *timespec) {
	waitq->timespec = *timespec;
	waitq->timer_trigger = EVENT_DEFAULT_TRIGGER(waitq);

	struct timer *timer = alloc(sizeof(struct timer));
	timer->timespec = *timespec;

	VECTOR_PUSH(timer->triggers, waitq->timer_trigger);
	VECTOR_PUSH(timer_list, timer);

	return 0;
}

int waitq_remove(struct waitq *waitq, struct waitq_trigger *trigger) {
	if(waitq == NULL || trigger == NULL) {
		return -1;
	}

	spinlock_irqsave(&trigger->lock);

	VECTOR_REMOVE_BY_VALUE(trigger->queues, waitq);

	trigger->refcnt--;
	if(trigger->refcnt == 0) {
		free(trigger);
	}

	spinrelease_irqsave(&trigger->lock);

	return 0;
}
