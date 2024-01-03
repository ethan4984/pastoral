#pragma once

#include <elf.h>

//#define SYSCALL_DEBUG_ALL

//#define SYSCALL_DEBUG_FD
//#define SYSCALL_DEBUG_SCHED
#define SYSCALL_DEBUG_SOCKET
#define SYSCALL_DEBUG_MEM
//#define SYSCALL_DEBUG_TIME
//#define SYSCALL_DEBUG_SIGNAL

struct registers;

void print(const char *str, ...);
void panic(const char *str, ...);
void view_registers(struct registers *regs);
void stacktrace(uint64_t *rbp);
void debug_init();

extern struct elf_file kernel_file;
