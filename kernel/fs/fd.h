#pragma once

#include <types.h>
#include <fs/vfs.h>
#include <lib/string.h>
#include <lib/cpu.h>


#define PIPE_BUFFER_SIZE 0x10000

struct fd_handle;
struct pipe;

struct file_handle {
	char lock;
	int refcnt;
	struct vfs_node *vfs_node;
	struct asset *asset;

	int flags;
	off_t position;

	VECTOR(struct dirent *) dirent_list;
	int current_dirent;

	struct pipe *pipe;
};

struct fd_handle {
	char lock;
	struct file_handle *file_handle;
	int fd_number;
	int flags;
};

struct pipe {
	struct file_handle *read;
	struct file_handle *write;
	void *buffer;
};

static inline void fd_init(struct fd_handle *handle) {
	memset(handle, 0, sizeof(*handle));
}

static inline void fd_lock(struct fd_handle *handle) {
	spinlock(&handle->lock);
}

static inline void fd_unlock(struct fd_handle *handle) {
	spinrelease(&handle->lock);
}

static inline void file_init(struct file_handle *handle) {
	memset(handle, 0, sizeof(*handle));
	handle->refcnt = 1;
}

static inline void file_lock(struct file_handle *handle) {
	spinlock(&handle->lock);
}

static inline void file_unlock(struct file_handle *handle) {
	spinrelease(&handle->lock);
}

// Use functions below when cloning a file descriptor.
static inline void file_get(struct file_handle *handle) {
	__atomic_fetch_add(&handle->refcnt, 1, __ATOMIC_RELAXED);
}


static inline void file_put(struct file_handle *handle) {
	if (__atomic_sub_fetch(&handle->refcnt, 1, __ATOMIC_RELAXED) == 0)
		free(handle);
}


struct fd_handle *fd_translate(int index);
ssize_t fd_write(int fd, const void *buf, size_t count);
ssize_t fd_read(int fd, void *buf, size_t count);
off_t fd_seek(int fd, off_t offset, int whence);
int fd_openat(int dirfd, const char *path, int flags);
int fd_close(int fd);
int fd_generate_dirent(struct fd_handle *dir_handle, struct vfs_node *node, struct dirent *entry);
