#pragma once

#include <stdint.h>
#include <stddef.h>

static inline void memset8(uint8_t *src, uint8_t data, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*src++ = data;
	}
}

static inline void memset16(uint16_t *src, uint16_t data, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*src++ = data;
	}
}

static inline void memset32(uint32_t *src, uint32_t data, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*src++ = data;
	}
}

static inline void memset64(uint64_t *src, uint64_t data, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*src++ = data;
	}
}

static inline void memcpy8(uint8_t *dest, uint8_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy16(uint16_t *dest, uint16_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy32(uint32_t *dest, uint32_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy64(uint64_t *dest, uint64_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline size_t strlen(const char *str) {
	size_t len = 0;
	while(str[len++]);
	return len;
}

int strcmp(const char *str0, const char *str1);
int strncmp(const char *str0, const char *str1, size_t n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
