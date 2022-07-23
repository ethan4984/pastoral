#pragma once

#include <types.h>
#include <vector.h>

#define TIMER_HZ 1000000000

struct waitq_trigger;

struct timer {
	struct timespec timespec;
	VECTOR(struct waitq_trigger*) triggers;
};

extern VECTOR(struct timer*) timer_list;

extern struct timespec clock_realtime;
extern struct timespec clock_monotonic;

struct timespec timespec_add(struct timespec a, struct timespec b);
struct timespec timespec_sub(struct timespec a, struct timespec b);
