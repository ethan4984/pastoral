#pragma once

#include <events/queue.h>
#include <hash.h>
#include <lock.h>

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

struct futex {
	struct spinlock lock;
	struct waitq waitq;
	struct waitq_trigger *trigger;
	uint64_t paddr;
	int locked;
	int expected;
	int operation;
};
