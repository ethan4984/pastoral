#include <stivale.h>
#include <cpu.h>
#include <debug.h>

static uint8_t stack[8192];

__attribute__((section(".stivalehdr"), used))
static struct stivale_header stivale_hdr = {
    .stack = (uintptr_t)stack + sizeof(stack),
    .flags = (1 << 0) | (1 << 1) | (1 << 3),
    .framebuffer_width  = 1024,
    .framebuffer_height = 768,
    .framebuffer_bpp = 32,
    .entry_point = 0
};

void pastoral_entry(struct stivale_struct *stivale_struct) {
	print("Pastoral unleashes the real power of the cpu\n");
	for(;;)
		asm ("hlt");
}
