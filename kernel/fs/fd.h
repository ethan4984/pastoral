#pragma once

#include <types.h>

struct fd_handle {
	struct asset *asset;
	int fd_number;
	int flags;
	off_t position;
};

struct fd_handle *fd_translate(int index);
ssize_t fd_write(int fd, const void *buf, size_t count);
ssize_t fd_read(int fd, void *buf, size_t count);
off_t fd_seek(int fd, off_t offset, int whence);
int fd_open(const char *path, int flags);
