#pragma once

#include <types.h>

#define DIV_ROUNDUP(a, b) (((a) + ((b) - 1)) / (b))
#define ALIGN_UP(a, b) (DIV_ROUNDUP(a, b) * b)
#define LENGTHOF(a) (sizeof(a) / sizeof(a[0]))
#define ABS(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))
#define BIT_SET(a, b) ((a)[(b) / 8] |= (1 << ((b) % 8)))
#define BIT_CLEAR(a, b) ((a)[(b) / 8] &= ~(1 << ((b) % 8)))
#define BIT_TEST(a, b) (((a)[(b) / 8] >> ((b) % 8)) & 0x1)

static inline size_t pow2_roundup(size_t a) {
	a--;
	a |= a >> 1;
	a |= a >> 2;
	a |= a >> 4;
	a |= a >> 8;
	a |= a >> 16;
	a++;
	return a;
}

static inline ssize_t pow(ssize_t base, ssize_t exp) {
    ssize_t result = 1;

    for(;;) { 
        if(exp & 1)
            result *= base;

        exp >>= 1;

        if(exp <= 0)
            break;

        base *= base;
    }

    return result;
}

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

static inline void memcpy8(uint8_t *dest, const uint8_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy16(uint16_t *dest, const uint16_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy32(uint32_t *dest, const uint32_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline void memcpy64(uint64_t *dest, const uint64_t *src, size_t n) {
	for(size_t i = 0; i < n; i++) {
		*dest++ = *src++;
	}
}

static inline size_t strlen(const char *str) {
	size_t len = 0;
	while(str[len]) len++;
	return len;
}

int strcmp(const char *str0, const char *str1);
int strncmp(const char *str0, const char *str1, size_t n);
int sprint(char *str, const char *format, ...);
int memcmp(const char *str0, const char *str, size_t n);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strchr(const char *str, char c);
void memcpy(void *dest, void *src, size_t n);
void memset(void *src, int data, size_t n);
