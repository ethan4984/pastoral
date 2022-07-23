#pragma once

#include <types.h>
#include <fs/vfs.h>
#include <lib/string.h>
#include <lib/cpu.h>
#include <sched/sched.h>

#define PIPE_BUFFER_SIZE 0x10000

#define STAT_ACCESS (1 << 0)
#define STAT_MOD (1 << 1)
#define STAT_STATUS (1 << 2)

struct fd_handle;
struct pipe;

struct file_handle {
	char lock;
	int refcnt;

	struct vfs_node *vfs_node;
	struct file_ops *ops;

	int flags;
	off_t position;

	struct {
		VECTOR(struct dirent *) dirent_list;
		int current_dirent;
	};
	struct pipe *pipe;

	struct waitq *waitq;
	struct waitq_trigger *trigger;

	// Pointer untouched by the kernel, use it on drivers.
	void *private_data;

	// This pointer is used for files that are not present in the VFS.
	struct stat *stat;
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

struct file_ops {
	int (*open)(struct vfs_node *, struct file_handle *);
	int (*close)(struct vfs_node *, struct file_handle *);

	ssize_t (*read)(struct file_handle *, void *, size_t, off_t);
	ssize_t (*write)(struct file_handle *, const void *, size_t, off_t);
	int (*ioctl)(struct file_handle *, uint64_t, void *);
	int (*truncate)(struct file_handle *, off_t);
	void *(*shared)(struct file_handle *, void *, off_t);
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


int stat_has_access(struct stat *stat, uid_t uid, gid_t gid, int mode);
int stat_update_time(struct stat *stat, int flags);
struct fd_handle *fd_translate(int index);
ssize_t fd_write(int fd, const void *buf, size_t count);
ssize_t fd_read(int fd, void *buf, size_t count);
off_t fd_seek(int fd, off_t offset, int whence);
int fd_openat(int dirfd, const char *path, int flags, mode_t mode);
int fd_close(int fd);
int fd_generate_dirent(struct fd_handle *dir_handle, struct vfs_node *node, struct dirent *entry);
int fd_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag);
