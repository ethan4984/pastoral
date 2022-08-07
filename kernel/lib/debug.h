#pragma once

#include <elf.h>

#define SYSCALL_DEBUG

struct registers;

void print(const char *str, ...);
void panic(const char *str, ...);
void view_registers(struct registers *regs);
void stacktrace(uint64_t *rbp);

extern struct symbol_list kernel_symbol_list;
