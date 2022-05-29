#include <fs/fd.h>
#include <vector.h>
#include <cpu.h>
#include <sched/sched.h>
#include <errno.h>
#include <bitmap.h>
#include <string.h>
#include <fs/vfs.h>
#include <debug.h>

static char fd_lock;

struct fd_handle *fd_translate(int index) {
	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		return NULL;
	}

	spinlock(&fd_lock);
	struct fd_handle *handle = hash_table_search(&current_task->fd_list, &index, sizeof(index));
	spinrelease(&fd_lock);

	return handle;
}

off_t fd_seek(int fd, off_t offset, int whence) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->asset->stat;
	if(S_ISFIFO(stat->st_mode) || S_ISSOCK(stat->st_mode)) {
		set_errno(ESPIPE);
		return -1;
	}

	switch(whence) {
		case SEEK_SET:
			fd_handle->position = offset;
			break;
		case SEEK_CUR:
			fd_handle->position += offset;
			break;
		case SEEK_END:
			fd_handle->position = stat->st_size + offset; 
			break;
		default:
			set_errno(EINVAL);
			return -1;
	}
	
	return fd_handle->position;
}

ssize_t fd_write(int fd, const void *buf, size_t count) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->asset->stat;
	if(S_ISFIFO(stat->st_mode) || S_ISSOCK(stat->st_mode)) {
		set_errno(ESPIPE);
		return -1;
	}

	struct asset *asset = fd_handle->asset;

	if(asset->write == NULL) {
		set_errno(EINVAL);
		return -1;
	}

	ssize_t ret = asset->write(asset, NULL, fd_handle->position, count, buf);

	if(ret != -1) {
		fd_handle->position += ret;
	}

	return ret;
}

ssize_t fd_read(int fd, void *buf, size_t count) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->asset->stat;
	if(S_ISDIR(stat->st_mode)) {
		set_errno(EISDIR);
		return -1; 
	}

	struct asset *asset = fd_handle->asset;

	if(asset->read == NULL) {
		set_errno(EINVAL);
		return -1;
	}

	ssize_t ret = asset->read(asset, NULL, fd_handle->position, count, buf);

	if(ret != -1) {
		fd_handle->position += ret;
	}

	return ret;
}

int fd_open(const char *path, int flags) {
	if(strlen(path) > MAX_PATH_LENGTH) {
		set_errno(ENAMETOOLONG);
		return -1;
	}

	struct vfs_node *vfs_node = vfs_search_absolute(NULL, path);

	if(flags & O_CREAT && vfs_node == NULL) {
		/* TODO */
	} else if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));

	*new_handle = (struct fd_handle) {
		.asset = vfs_node->asset,
		.fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap),
		.flags = flags,
		.position = 0
	};

	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	hash_table_push(&current_task->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));

	return new_handle->fd_number;
}

int fd_close(int fd) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	hash_table_delete(&current_task->fd_list, &fd_handle->fd_number, sizeof(fd_handle->fd_number));
	bitmap_free(&current_task->fd_bitmap, fd_handle->fd_number);
	
	return 0;
}

int fd_stat(int fd, void *buffer) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = buffer;
	*stat = *fd_handle->asset->stat;

	return 0;
}

int fd_statat(int dirfd, const char *path, void *buffer, int) {
	struct vfs_node *dir = CURRENT_THREAD->cwd;

	if(dirfd != 0xFFFFFF9C) {
		struct fd_handle *fd_handle = fd_translate(dirfd);
		if(fd_handle == NULL) {
			set_errno(EBADF);
			return -1;
		}

		if(!S_ISDIR(fd_handle->asset->stat->st_mode)) {
			set_errno(EBADF);
			return -1;
		}

		dir = fd_handle->vfs_node;
	}

	struct vfs_node *vfs_node = vfs_search_absolute(dir, path);
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}
	
	struct stat *stat = buffer;
	*stat = *vfs_node->asset->stat;

	return 0;
}

int fd_dup(int fd) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));
	*new_handle = *fd_handle;

	new_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap);

	return new_handle->fd_number;
}

int fd_dup2(int oldfd, int newfd) {
	struct fd_handle *oldfd_handle = fd_translate(oldfd);
	if(oldfd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	if(BIT_TEST(CURRENT_TASK->fd_bitmap.data, newfd)) {
		fd_close(newfd);
	} else {
		BIT_SET(CURRENT_TASK->fd_bitmap.data, newfd);
	}

	struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));
	*new_handle = *oldfd_handle;

	new_handle->fd_number = newfd;

	return new_handle->fd_number;
}

void syscall_dup2(struct registers *regs) {
	int oldfd = regs->rdi;
	int newfd = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: dup2: oldfd {%x}, newfd {%x}\n", oldfd, newfd);
#endif

	regs->rax = fd_dup2(oldfd, newfd);
}

void syscall_dup(struct registers *regs) {
	int fd = regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: dup: fd {%x}\n", fd);
#endif

	regs->rax = fd_dup(fd);
}

void syscall_stat(struct registers *regs) {
	int fd = regs->rdi;
	void *buf = (void*)regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: stat: fd {%x}, buf {%x}\n", fd, (uintptr_t)buf);
#endif

	regs->rax = fd_stat(fd, buf);
}

void syscall_statat(struct registers *regs) {
	int dirfd = regs->rdi;
	const char *path = (void*)regs->rsi;
	void *buf = (void*)regs->rdx;
	int flags = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: statat: dirfd {%x}, path {%s}, buf {%x}, flags {%x}\n", dirfd, path, (uintptr_t)buf, flags);
#endif

	regs->rax = fd_statat(dirfd, path, buf, flags);
}

void syscall_write(struct registers *regs) {
	int fd = regs->rdi;
	const void *buf = (const void*)regs->rsi;
	size_t cnt = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: write: fd {%x}, buf {%x}, cnt {%x}\n", fd, (uintptr_t)buf, cnt);
#endif

	regs->rax = fd_write(fd, buf, cnt);
}

void syscall_read(struct registers *regs) {
	int fd = regs->rdi;
	void *buf = (void*)regs->rsi;
	size_t cnt = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: read: fd {%x}, buf {%x}, cnt {%x}\n", fd, (uintptr_t)buf, cnt);
#endif

	regs->rax = fd_read(fd, buf, cnt);
}

void syscall_seek(struct registers *regs) {
	int fd = regs->rdi;
	off_t offset = regs->rsi;
	int whence = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: seek: fd {%x}, offset {%x}, whence {%x}\n", fd, offset, whence);
#endif

	regs->rax = fd_seek(fd, offset, whence);
}

void syscall_open(struct registers *regs) {
	const char *pathname = (const char*)regs->rdi;
	int flags = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: open: pathname {%s}, flags {%x}\n", pathname, flags);
#endif

	regs->rax = fd_open(pathname, flags); 
}

void syscall_close(struct registers *regs) {
	int fd = regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: close: fd {%x}\n", fd);
#endif

	regs->rax = fd_close(fd);
}

void syscall_fcntl(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: fcntl: fd {%x}, cmd {%x}\n", regs->rdi, regs->rsi);
#endif

	struct fd_handle *fd_handle = fd_translate(regs->rdi);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

    switch(regs->rsi) {
        case F_DUPFD:
			regs->rax = fd_dup(regs->rdi);
            break;
        case F_GETFD:
            regs->rax = (uint64_t)((fd_handle->flags & O_CLOEXEC) ? O_CLOEXEC : 0);
            break;
        case F_SETFD:
            fd_handle->flags = (uint64_t)((fd_handle->flags & O_CLOEXEC) ? O_CLOEXEC : 0);
            regs->rax = 0;
            break;
        case F_GETFL:
            regs->rax = fd_handle->flags;
            break;
        case F_SETFL:
            fd_handle->flags = regs->rdx;
            regs->rax = 0;
            break;
        default:
            print("fnctl unknown command %x\n", regs->rsi);
            set_errno(EINVAL);
            regs->rax = -1;
    }
}
