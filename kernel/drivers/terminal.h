#pragma once

#include <limine.h>
#include <vector.h>

struct terminal {
	struct limine_terminal *limine_terminal;

	bool caplock;
	bool shift;
	bool ctrl;

	char *stream;
	volatile size_t stream_index;
	size_t stream_capacity;

	char lock;
};

void limine_terminal_init();
void limine_terminal_print(char *str, size_t length);

ssize_t terminal_read(struct asset*, void*, off_t, off_t, void*);
ssize_t terminal_write(struct asset*, void*, off_t, off_t, const void*);

extern VECTOR(struct terminal*) terminal_list;
extern struct terminal *current_terminal;
