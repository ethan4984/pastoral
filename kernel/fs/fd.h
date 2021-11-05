#pragma once

#include <fs/vfs.h>

struct fd_handle {
	ssize_t flags;
	struct vfs_node *vfs_node;
	int fd_number;
	off_t position;
};

struct fd_handle *translate_fd_index(int index);
