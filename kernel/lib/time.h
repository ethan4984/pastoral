#pragma once

#include <types.h>

extern struct timespec clock_realtime;
extern struct timespec clock_monotonic;

void time_add_interval(struct timespec *dest, struct timespec *interval);
