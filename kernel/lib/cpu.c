#include <cpu.h>

uint64_t HIGH_VMA = 0xffff800000000000;

extern void syscall_main();

struct cpuid_state cpuid(size_t leaf, size_t subleaf) {
	struct cpuid_state ret = { .leaf = leaf, subleaf = subleaf };

	size_t max;
	asm volatile ("cpuid" : "=a"(max) : "a"(leaf & 0x80000000) : "rbx", "rcx", "rdx");

	if(leaf > max) {
		return ret;
	}

	asm volatile ("cpuid" : "=a"(ret.rax), "=b"(ret.rbx), "=c"(ret.rcx), "=d"(ret.rbx) : "a"(leaf), "c"(subleaf));

	return ret;
}

void init_cpu_features() {
	wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 1); // set SCE
	wrmsr(MSR_STAR, 0x13ull << 48 | 0x8ull << 32);
	wrmsr(MSR_LSTAR, (uintptr_t)syscall_main);
	wrmsr(MSR_SFMASK, ~(uint32_t)2);

	uint64_t cr0;
	asm volatile ("mov %%cr0, %0" : "=r"(cr0));

	cr0 &= ~(1 << 2); // ensure EM=0
	cr0 |= (1 << 1); // set MP=0

	asm volatile ("mov %0, %%cr0" :: "r"(cr0));

	uint64_t cr4;
	asm volatile ("mov %%cr4, %0" : "=r"(cr4));

	cr4 |=	(1 << 7) | // Set PGE (allow for global pages)
			(1 << 9) | // Enables SSE and fxsave/fxrstor
			(1 << 10); // Enables unmasked SSE exceptions
											
	asm volatile ("mov %0, %%cr4" :: "r"(cr4));
}
