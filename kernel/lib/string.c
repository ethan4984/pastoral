#include <string.h>

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

void memcpy(void *dest, void *src, size_t n) {
	memcpy8(dest, src, n);
}

void memset(void *src, int data, size_t n) {
	memset8(src, data, n);
}
