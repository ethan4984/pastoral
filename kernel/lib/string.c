#include <string.h>
#include <stdarg.h>

int strcmp(const char *str0, const char *str1) {
	for(size_t i = 0;; i++) {
		if(str0[i] != str1[i]) {
			return str0[i] - str1[i];
		}

		if(!str0[i]) {
			return 0;
		}
	}
}

int strncmp(const char *str0, const char *str1, size_t n) {
	for(size_t i = 0; i < n; i++) {
		if(str0[i] != str1[i]) {
			return str0[i] - str1[i];
		}

		if(!str0[i]) {
			return 0;
		}
	}

	return 0;
}

char *strcpy(char *dest, const char *src) {
	size_t i = 0;

	for(; src[i]; i++) {
		dest[i] = src[i];
	}

	dest[i] = 0;

	return dest;
}

char *strncpy(char *dest, const char *src, size_t n) {
	size_t i = 0;

	for(; i < n && src[i]; i++) {
		dest[i] = src[i];
	}

	dest[i] = 0;

	return dest;
}

char *strchr(const char *str, char c) {
	while(*str++) {
		if(*str == c) {
			return (char*)str;
		}
	}
	return NULL;
}

int memcmp(const char *str0, const char *str1, size_t n) {
	for(size_t i = 0; i < n; i++) {
		if(str0[i] != str1[i]) {
			return str0[i] - str1[i];
		}
	}

	return 0;
}

static void sprint_print_number(char *str, int *write_cnt, size_t number, int base) {
	static char characters[] = "0123456789ABCDEF";
	int arr[50], cnt = 0;

	do {
		arr[cnt++] = number % base;
		number /= base;
	} while(number);

	for(int i = cnt - 1; i > -1; i--) {
		str[(*write_cnt)++] = characters[arr[i]];
	}
}

int sprint(char *str, const char *format, ...) {
	va_list arg;
	va_start(arg, format);

	int write_cnt = 0;

	for(size_t i = 0; i < strlen(format); i++) {
		if(format[i] != '%') {
			str[write_cnt++] = format[i];
		} else {
			switch(format[++i]) {
				case 'd': {
					uint64_t number = va_arg(arg, uint64_t);
					sprint_print_number(str, &write_cnt, number, 10);
					break;
				}
				case 's': {
					const char *string = va_arg(arg, const char*);

					for(size_t i = 0; i < strlen(string); i++) {
						str[write_cnt++] = string[i];
					}

					break;
				}
				case 'c': {
					char c = va_arg(arg, int);
					str[write_cnt++] = c;
					break;
				}
				case 'x': {
					uint64_t number = va_arg(arg, uint64_t);
					sprint_print_number(str, &write_cnt, number, 16);

					break;
				}
				case 'b': {
					uint64_t number = va_arg(arg, uint64_t);
					sprint_print_number(str, &write_cnt, number, 2);
					break;
				}
			}
		}
	}

	str[write_cnt++] = '\0';

	va_end(arg);

	return write_cnt - 1;
}

void memcpy(void *dest, const void *src, size_t n) {
	memcpy8(dest, src, n);
}

void memset(void *src, int data, size_t n) {
	memset8(src, data, n);
}
