#include <int/idt.h> 
#include <sched/sched.h>
#include <int/apic.h>
#include <lib/cpu.h>
#include <time.h>
#include <debug.h>
#include <limine.h>

#define PIT_FREQ 1000

struct timespec clock_realtime;
struct timespec clock_monotonic;

typeof(timer_list) timer_list;

static volatile struct limine_boot_time_request limine_boot_time_request = {
	.id = LIMINE_BOOT_TIME_REQUEST,
	.revision = 0
};

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

void pit_handler(struct registers*, void*) {
	struct timespec interval = { .tv_sec = 0, .tv_nsec = TIMER_HZ / PIT_FREQ };

	clock_realtime = timespec_add(clock_realtime, interval);
	clock_monotonic = timespec_add(clock_monotonic, interval);

	for(size_t i = 0; i < timer_list.length; i++) {
		struct timer *timer = timer_list.data[i];

		timer->timespec = timespec_sub(timer->timespec, interval);

		if(timer->timespec.tv_nsec == 0 && timer->timespec.tv_sec == 0) {
			for(size_t j = 0; j < timer->triggers.length; j++) {
				struct waitq_trigger *trigger = timer->triggers.data[j];
				waitq_trigger_calibrate(trigger, CURRENT_TASK, CURRENT_THREAD, EVENT_TIMER);
				waitq_wake(trigger);
			}
			
			VECTOR_REMOVE_BY_INDEX(timer_list, i);
		}
	}
}

void pit_init() {
	int divisor = 1193182 / PIT_FREQ;

	if((1193182 % PIT_FREQ) > (PIT_FREQ / 2)) { // round up
		divisor++;
	}

	outb(0x43, (0b010 << 1) | (0b11 << 4)); // channel 0, lobyte/hibyte, rate generator
	outb(0x40, divisor & 0xff);
	outb(0x40, divisor >> 8 & 0xff);

	int vector = idt_alloc_vector(pit_handler, NULL);

	ioapic_set_irq_redirection(xapic_read(XAPIC_ID_REG_OFF), vector, 0, false);

	int64_t epoch = limine_boot_time_request.response->boot_time;

	clock_realtime = (struct timespec) { .tv_sec = epoch, .tv_nsec = 0 };
	clock_monotonic = (struct timespec) { .tv_sec = epoch, .tv_nsec = 0 };
}
