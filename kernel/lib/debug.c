#include <debug.h>
#include <cpu.h>
#include <string.h>
#include <stdarg.h>
#include <drivers/tty.h>

static void serial_write(uint8_t data) {
	if(current_tty) {
		tty_putchar(current_tty, data);
	}

	while((inb(COM1 + 5) & (1 << 5)) == 0);
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

void print(const char *str, ...) {
	va_list arg;
	va_start(arg, str);

	print_internal(str, arg);

	va_end(arg);
}

void panic(const char *str, ...) {
	print("KERNEL PANIC: < ");

	va_list arg;
	va_start(arg, str);

	print_internal(str, arg);

	va_end(arg);

	print(" > HALTING\n");
	
	for(;;)
		asm volatile ("cli\nhlt");
}
