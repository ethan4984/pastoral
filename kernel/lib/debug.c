#include <debug.h>
#include <cpu.h>
#include <string.h>
#include <stdarg.h>

static void serial_write(uint8_t data) {
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

void print(const char *str, ...) {
	va_list arg;
	va_start(arg, str);

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
					serial_write('0');
					serial_write('x');

					uint64_t number = va_arg(arg, uint64_t);
					serial_print_number(number, 16);

					break;
				}
				case 'b': {
					serial_write('0');
					serial_write('b');

					uint64_t number = va_arg(arg, uint64_t);
					serial_print_number(number, 2);
					break;
				}
			}
		}
	}

	va_end(arg);
}
