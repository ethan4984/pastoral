#include <int/idt.h> 
#include <int/apic.h>
#include <lib/cpu.h>
#include <time.h>
#include <debug.h>
#include <limine.h>

#define TIMER_FREQ 1000
#define PIT_FREQ 1193182

struct timespec clock_realtime;
struct timespec clock_monotonic;

static volatile struct limine_boot_time_request limine_boot_time_request = {
	.id = LIMINE_BOOT_TIME_REQUEST,
	.revision = 0
};

void pit_handler(struct registers*, void*) {
	struct timespec interval = { .tv_sec = 0, .tv_nsec = 1000000000 / TIMER_FREQ };

	time_add_interval(&clock_realtime, &interval);
	time_add_interval(&clock_monotonic, &interval);
}

void pit_init() {
	int divisor = PIT_FREQ / TIMER_FREQ;

	if((TIMER_FREQ % TIMER_FREQ) > (TIMER_FREQ / 2)) { // round up
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
