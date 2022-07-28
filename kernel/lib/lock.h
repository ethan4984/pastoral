#pragma once

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

static inline void spinlock_irqsave(struct spinlock *spinlock) {
	uint64_t rflags;
	asm volatile ("pushfq\n\tpop %0" : "=r"(rflags));
	spinlock->interrupts = (rflags >> 9) & 1;

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
