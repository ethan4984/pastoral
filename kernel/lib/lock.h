#pragma once

struct sched_thread;

struct spinlock {
	char lock;
	bool interrupts;
};

static inline void raw_spinlock(void *lock) {
	while(__atomic_test_and_set(lock, __ATOMIC_ACQUIRE));
}

static inline void raw_spinrelease(void *lock) {
	__atomic_clear(lock, __ATOMIC_RELEASE);
}

bool get_interrupt_state();

static inline void spinlock_irqdef(struct spinlock *spinlock) {
	raw_spinlock(&spinlock->lock);
}

static inline void spinrelease_irqdef(struct spinlock *spinlock) {
	raw_spinrelease(&spinlock->lock);
}

static inline void spinlock_irqsave(struct spinlock *spinlock) {
	spinlock->interrupts = get_interrupt_state();
	asm volatile ("cli");
	raw_spinlock(&spinlock->lock);
}

static inline void spinrelease_irqsave(struct spinlock *spinlock) {
	raw_spinrelease(&spinlock->lock);

	if(spinlock->interrupts) {
		asm volatile ("sti");
	} else {
		asm volatile ("cli");
	}
}
