#pragma once

//#define SYSCALL_DEBUG

struct registers;

void print(const char *str, ...);
void panic(const char *str, ...);
void view_registers(struct registers *regs);
