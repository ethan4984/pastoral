#include <drivers/timer.h>
#include <events/queue.h>
#include <sched/sched.h>
#include <debug.h>
#include <errno.h>
#include <cpu.h>

struct timespec clock_realtime = { 0, 0 };
struct timespec clock_monotonic = { 0, 0 };

void syscall_usleep(struct registers *regs) {
	const struct timespec *req = (void*)regs->rdi;
	struct timespec *rem = (void*)regs->rsi; 

#if defined(SYSCALL_DEBUG_TIME)
	print("syscall: [pid %x, tid %x] usleep: req {%x}, rem {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, req, rem);
#endif

	waitq_set_timer(CURRENT_TASK->waitq, req);

	for(;;) {
		if(CURRENT_TASK->waitq->timer_trigger->fired) {
			break;
		}

		int ret = waitq_block(CURRENT_TASK->waitq, NULL);
		if(ret == -1) {
			regs->rax = -1;
			goto finish;
		}
	}

	*rem = *req;
	regs->rax = 0;
finish:
	waitq_remove(CURRENT_TASK->waitq, CURRENT_TASK->waitq->timer_trigger);
}

void syscall_clock_gettime(struct registers *regs) {
	clockid_t clk_id = regs->rdi;
	struct timespec *tp = (void*)regs->rsi;

#if defined(SYSCALL_DEBUG_TIME)
	print("syscall: [pid %x, tid %x] clock_gettime: clk_id {%x}, tp {%x}\n", CORE_LOCAL->pid, CORE_LOCAL->tid, clk_id, tp);
#endif

	switch(clk_id) {
		case CLOCK_REALTIME:
			*tp = clock_realtime;
			break; 
		case CLOCK_MONOTONIC:
			*tp = clock_monotonic;
			break;
		default:
			set_errno(EINVAL); 
			regs->rax = -1; 
			return;
	}

	regs->rax = 0;
}

struct timespec timespec_add(struct timespec a, struct timespec b) {
	struct timespec ret = {
		.tv_nsec = a.tv_nsec + b.tv_nsec,
		.tv_sec = a.tv_sec + b.tv_sec
	};

	if(ret.tv_nsec > TIMER_HZ) {
		ret.tv_nsec -= TIMER_HZ;
		ret.tv_sec++;
	}

	return ret;
}

struct timespec timespec_sub(struct timespec a, struct timespec b) {
	struct timespec ret = {
		.tv_nsec = a.tv_nsec - b.tv_nsec,
		.tv_sec = a.tv_sec - b.tv_sec
	};

	if(ret.tv_nsec < 0) {
		ret.tv_nsec += TIMER_HZ;
		ret.tv_sec--;
	}

	if(ret.tv_sec < 0) {
		ret.tv_nsec = 0;
		ret.tv_sec = 0;
	}

	return ret;
}

struct timespec timespec_convert_ms(int ms) {
	struct timespec ret = {
		.tv_nsec = (ms % 1000) * 100000,
		.tv_sec = ms / 1000
	};

	return ret;
}
