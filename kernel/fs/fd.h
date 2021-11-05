#pragma once

#include <types.h>

struct fd_handle {
	struct asset *asset;
	int fd_number;
	int flags;
	off_t position;
};

struct fd_handle *translate_fd_index(int index);
