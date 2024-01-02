#pragma once

#include <types.h>
#include <time.h>

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7

extern struct timespec clock_realtime; 
extern struct timespec clock_monotonic;

struct timespec timespec_add(struct timespec a, struct timespec b);
struct timespec timespec_sub(struct timespec a, struct timespec b);
struct timespec timespec_convert_ms(int ms);
