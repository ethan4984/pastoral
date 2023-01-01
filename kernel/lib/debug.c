#include <debug.h>
#include <cpu.h>
#include <string.h>
#include <stdarg.h>
#include <lock.h>

struct elf_file kernel_file; 

void stacktrace(uint64_t *rbp) {
	for(;;) {
		if(rbp == NULL) {
			return;
		}

		uint64_t previous_rbp = *rbp;
		rbp++;
		uint64_t return_address = *rbp;

		if(return_address == 0) {
			return;
		}

		struct symbol *symbol = elf64_search_symtable(&kernel_file, return_address);

		if(symbol) { 
			print("trace: [%x] <%s+%x>\n", return_address, symbol->name, return_address - symbol->address);
		} else {
			print("trace: [%x]\n", return_address);
		}

		rbp = (void*)previous_rbp;
	}
}

static void serial_write(uint8_t data) {
	while((inb(COM1 + 5) & (1 << 5)) == 0);

	// use '__builtin_expect' to assume 'data' isn't a newline
	if (__builtin_expect(data == '\n', 0)) {
		outb(COM1, '\r');
	}

	outb(COM1, data);
}

static void serial_print_number(size_t number, int base) {
	static char characters[] = "0123456789ABCDEF";
	int arr[50], cnt = 0;

	do {
		arr[cnt++] = number % base;
		number /= base;
	} while(number);

	for(int i = cnt - 1; i > -1; i--) {
		serial_write(characters[arr[i]]);
	}
}

static void print_internal(const char *str, va_list arg) {
	for(size_t i = 0; i < strlen(str); i++) {
		if(str[i] != '%') {
			serial_write(str[i]);
		} else {
			switch(str[++i]) {
				case 'd': {
					uint64_t number = va_arg(arg, uint64_t);
					serial_print_number(number, 10);
					break;
				}
				case 's': {
					const char *str = va_arg(arg, const char*);

					for(size_t i = 0; i < strlen(str); i++) {
						serial_write(str[i]);
					}

					break;
				}
				case 'c': {
					char c = va_arg(arg, int);
					serial_write(c);
					break;
				}
				case 'x': {
					uint64_t number = va_arg(arg, uint64_t);
					serial_print_number(number, 16);

					break;
				}
				case 'b': {
					uint64_t number = va_arg(arg, uint64_t);
					serial_print_number(number, 2);
					break;
				}
			}
		}
	}
}

static struct spinlock print_lock;

void print(const char *str, ...) {
	va_list arg;
	va_start(arg, str);

	spinlock_irqsave(&print_lock);
	print_internal(str, arg);
	spinrelease_irqsave(&print_lock);

	va_end(arg);
}

void panic(const char *str, ...) {
	print("KERNEL PANIC: < ");

	va_list arg;
	va_start(arg, str);

	print_internal(str, arg);

	va_end(arg);

	print(" > HALTING\n");

	uint64_t rbp;
	asm volatile ("mov %%rbp, %0" : "=r"(rbp));
	stacktrace((void*)rbp);

	for(;;)
		asm volatile ("cli\nhlt");
}

void view_registers(struct registers *regs) {
	print("debug: rax: %x\n", regs->rax);
	print("debug: rbx: %x\n", regs->rbx);
	print("debug: rcx: %x\n", regs->rcx);
	print("debug: rdx: %x\n", regs->rdx);
	print("debug: rbp: %x\n", regs->rbp);
	print("debug: rdi: %x\n", regs->rdi);
	print("debug: rsi: %x\n", regs->rsi);
	print("debug: r8: %x\n", regs->r8);
	print("debug: r9: %x\n", regs->r9);
	print("debug: r10: %x\n", regs->r10);
	print("debug: r11: %x\n", regs->r11);
	print("debug: r12: %x\n", regs->r12);
	print("debug: r13: %x\n", regs->r13);
	print("debug: r14: %x\n", regs->r14);
	print("debug: r15: %x\n", regs->r15);
	print("debug: rip: %x\n", regs->rip);
	print("debug: cs: %x\n", regs->cs);
	print("debug: rflags: %x\n", regs->rflags);
	print("debug: rsp: %x\n", regs->rsp);
	print("debug: ss: %x\n", regs->ss);
}

void debug_init() {
	// setup the serial controller
	outb(COM1 + 3, 0x80);   // enable DLAB (to set the baud rate to 9600)
	outb(COM1 + 0, 0x0C);   // Set divisor to 12 (hi) and 0 (lo)
	outb(COM1 + 1, 0x00);
	outb(COM1 + 3, 0x03);   // 8 bits, no parity, one stop bit
	outb(COM1 + 2, 0xC7);   // setup the FIFOs with a 14-byte threshold
	outb(COM1 + 4, 0x0);    // finally, enable the port with IRQs disabled
}
