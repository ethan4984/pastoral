#include <time.h>

void time_add_interval(struct timespec *dest, struct timespec *interval) {
	if(dest->tv_nsec + interval->tv_nsec > 999999999) {
		dest->tv_nsec = dest->tv_nsec + interval->tv_nsec - 1000000000;
		dest->tv_sec++;
	} else {
		dest->tv_nsec += interval->tv_nsec;
	}

	dest->tv_sec += interval->tv_sec;
}
