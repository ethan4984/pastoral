#include <fs/fd.h>
#include <vector.h>
#include <cpu.h>
#include <sched/sched.h>
#include <errno.h>
#include <bitmap.h>
#include <string.h>
#include <fs/vfs.h>
#include <debug.h>
#include <time.h>
#include <mm/pmm.h>

static char fd__lock;

struct fd_handle *fd_translate(int index) {
	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		return NULL;
	}

	spinlock(&fd__lock);
	struct fd_handle *handle = hash_table_search(&current_task->fd_list, &index, sizeof(index));
	spinrelease(&fd__lock);

	return handle;
}

off_t fd_seek(int fd, off_t offset, int whence) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->file_handle->asset->stat;
	if(S_ISFIFO(stat->st_mode) || S_ISSOCK(stat->st_mode)) {
		set_errno(ESPIPE);
		return -1;
	}

	file_lock(fd_handle->file_handle);
	switch(whence) {
		case SEEK_SET:
			fd_handle->file_handle->position = offset;
			break;
		case SEEK_CUR:
			fd_handle->file_handle->position += offset;
			break;
		case SEEK_END:
			fd_handle->file_handle->position = stat->st_size + offset;
			break;
		default:
			file_unlock(fd_handle->file_handle);
			set_errno(EINVAL);
			return -1;
	}

	off_t pos =  fd_handle->file_handle->position;
	file_unlock(fd_handle->file_handle);
	return pos;
}

ssize_t fd_write(int fd, const void *buf, size_t count) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct asset *asset = fd_handle->file_handle->asset;
	struct stat *stat = asset->stat;

	if(asset->write == NULL) {
		set_errno(EINVAL);
		return -1;
	}

	ssize_t ret;
	if(S_ISFIFO(stat->st_mode) && fd_handle->file_handle->pipe) {
		ret = asset->write(asset, fd_handle->file_handle->pipe->buffer, fd_handle->file_handle->position, count, buf);
	} else {
		ret = asset->write(asset, NULL, fd_handle->file_handle->position, count, buf);
	}

	if(ret != -1) {
		fd_handle->file_handle->position += ret;
	}

	return ret;
}

ssize_t fd_read(int fd, void *buf, size_t count) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->file_handle->asset->stat;
	if(S_ISDIR(stat->st_mode)) {
		set_errno(EISDIR);
		return -1;
	}

	struct asset *asset = fd_handle->file_handle->asset;

	if(asset->read == NULL) {
		set_errno(EINVAL);
		return -1;
	}

	ssize_t ret;
	if(S_ISFIFO(stat->st_mode) && fd_handle->file_handle->pipe) {
		ret = asset->read(asset, fd_handle->file_handle->pipe->buffer, fd_handle->file_handle->position, count, buf);
	} else {
		ret = asset->read(asset, NULL, fd_handle->file_handle->position, count, buf);
	}

	if(ret != -1) {
		fd_handle->file_handle->position += ret;
	}

	return ret;
}

ssize_t pipe_read(struct asset *asset, void *out, off_t offset, off_t cnt, void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	if(offset > stat->st_size) {
		event_wait(asset->event, EVENT_FD_WRITE);
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		cnt = stat->st_size - offset;
	}

	memcpy8(buf, out + offset, cnt);

	spinrelease(&asset->lock);

	return cnt;
}

ssize_t pipe_write(struct asset *asset, void *out, off_t offset, off_t cnt, const void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	if(offset >= PIPE_BUFFER_SIZE) {
		set_errno(EINVAL);
		return -1;
	}

	if(offset + cnt > PIPE_BUFFER_SIZE) {
		cnt = stat->st_size - offset;
	}

	if(offset > stat->st_size) {
		asset->trigger->event_type = EVENT_FD_WRITE;
		asset->trigger->agent_task = CURRENT_TASK;
		asset->trigger->agent_thread = CURRENT_THREAD;
		event_fire(asset->trigger);
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		stat->st_size += offset + cnt - stat->st_size;
	}

	memcpy8(out + offset, buf, cnt);

	spinrelease(&asset->lock);

	return cnt;
}

int fd_openat(int dirfd, const char *path, int flags) {
	if(strlen(path) > MAX_PATH_LENGTH) {
		set_errno(ENAMETOOLONG);
		return -1;
	}

	int relative = *path == '/' ? 0 : 1;
	struct vfs_node *dir;

	if(!relative) {
		dir = vfs_root;
	} else {
		if(dirfd == AT_FDCWD) {
			dir = CURRENT_TASK->cwd;
		} else {
			struct fd_handle *fd_handle = fd_translate(dirfd);
			if(fd_handle == NULL) {
				set_errno(EBADF);
				return -1;
			}

			dir = fd_handle->file_handle->vfs_node;
		}
	}

	struct vfs_node *vfs_node = vfs_search_absolute(dir, path, true);

	if(flags & O_CREAT && vfs_node == NULL) {
		struct vfs_node *parent = vfs_parent_dir(dir, path);
		if(parent == NULL) {
			set_errno(ENOENT);
			return -1;
		}

		struct asset *asset = alloc(sizeof(struct asset));
		struct stat *stat = alloc(sizeof(struct stat));

		asset_init(asset);
		asset->stat = stat;
		asset->read = parent->asset->read;
		asset->write = parent->asset->write;
		asset->ioctl = parent->asset->ioctl;
		asset->resize = parent->asset->resize;
		asset->event = alloc(sizeof(struct event));
		asset->trigger = alloc(sizeof(struct event_trigger));
		asset->trigger->event = asset->event;

		stat->st_atim = clock_realtime;
		stat->st_mtim = clock_realtime;
		stat->st_ctim = clock_realtime;

		stat->st_mode = S_IFREG;

		vfs_node = vfs_create_node_deep(parent, asset, parent->filesystem, path);
	} else if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	} /*else if(flags & O_CREAT && flags & O_EXEC) {
		set_errno(EEXIST);
		return -1;
	}*/

	struct fd_handle *new_fd_handle = alloc(sizeof(struct fd_handle));
	struct file_handle *new_file_handle = alloc(sizeof(struct file_handle));

	fd_init(new_fd_handle);
	file_init(new_file_handle);

	new_fd_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap);
	new_fd_handle->file_handle = new_file_handle;
	new_fd_handle->flags = flags & O_CLOEXEC;

	new_file_handle->vfs_node = vfs_node;
	new_file_handle->asset = vfs_node->asset;
	new_file_handle->flags = flags & ~O_CLOEXEC;

	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	hash_table_push(&current_task->fd_list, &new_fd_handle->fd_number, new_fd_handle, sizeof(new_fd_handle->fd_number));

	return new_fd_handle->fd_number;
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

	file_put(fd_handle->file_handle);

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
	*stat = *fd_handle->file_handle->asset->stat;

	return 0;
}

int fd_statat(int dirfd, const char *path, void *buffer, int flags) {
	if(!strlen(path) && !(flags & AT_EMPTY_PATH)) {
		set_errno(ENOENT);
		return -1;
	}

	bool symfollow = flags & AT_SYMLINK_NOFOLLOW ? false : true;
	struct vfs_node *vfs_node;

	if(flags & AT_EMPTY_PATH) {
		struct fd_handle *fd_handle = fd_translate(dirfd);
		if(fd_handle == NULL) {
			set_errno(EBADF);
			return -1;
		}

		vfs_node = fd_handle->file_handle->vfs_node;
	} else {
		int relative = *path == '/' ? 0 : 1;
		struct vfs_node *dir;

		if(!relative) {
			dir = vfs_root;
		} else {
			if(dirfd == AT_FDCWD) {
				dir = CURRENT_TASK->cwd;
			} else {
				struct fd_handle *fd_handle = fd_translate(dirfd);
				if(fd_handle == NULL) {
					set_errno(EBADF);
					return -1;
				}

				if(!S_ISDIR(fd_handle->file_handle->asset->stat->st_mode)) {
					set_errno(EBADF);
					return -1;
				}

				dir = fd_handle->file_handle->vfs_node;
			}
		}

		vfs_node = vfs_search_absolute(dir, path, symfollow);
		if(vfs_node == NULL) {
			set_errno(ENOENT);
			return -1;
		}
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
	file_get(new_handle->file_handle);
	new_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap);

	hash_table_push(&CURRENT_TASK->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));

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
	file_get(new_handle->file_handle);
	new_handle->fd_number = newfd;

	hash_table_push(&CURRENT_TASK->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));

	return new_handle->fd_number;
}

void syscall_dup2(struct registers *regs) {
	int oldfd = regs->rdi;
	int newfd = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] dup2: oldfd {%x}, newfd {%x}\n", CORE_LOCAL->pid, oldfd, newfd);
#endif

	regs->rax = fd_dup2(oldfd, newfd);
}

void syscall_dup(struct registers *regs) {
	int fd = regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] dup: fd {%x}\n", CORE_LOCAL->pid, fd);
#endif

	regs->rax = fd_dup(fd);
}

void syscall_stat(struct registers *regs) {
	int fd = regs->rdi;
	void *buf = (void*)regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] stat: fd {%x}, buf {%x}\n", CORE_LOCAL->pid, fd, (uintptr_t)buf);
#endif

	regs->rax = fd_stat(fd, buf);
}

void syscall_statat(struct registers *regs) {
	int dirfd = regs->rdi;
	const char *path = (void*)regs->rsi;
	void *buf = (void*)regs->rdx;
	int flags = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] statat: dirfd {%x}, path {%s}, buf {%x}, flags {%x}\n", CORE_LOCAL->pid, dirfd, path, (uintptr_t)buf, flags);
#endif

	regs->rax = fd_statat(dirfd, path, buf, flags);
}

void syscall_write(struct registers *regs) {
	int fd = regs->rdi;
	const void *buf = (const void*)regs->rsi;
	size_t cnt = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] write: fd {%x}, buf {%x}, cnt {%x}\n", CORE_LOCAL->pid, fd, (uintptr_t)buf, cnt);
#endif

	regs->rax = fd_write(fd, buf, cnt);
}

void syscall_read(struct registers *regs) {
	int fd = regs->rdi;
	void *buf = (void*)regs->rsi;
	size_t cnt = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] read: fd {%x}, buf {%x}, cnt {%x}\n", CORE_LOCAL->pid, fd, (uintptr_t)buf, cnt);
#endif

	regs->rax = fd_read(fd, buf, cnt);
}

void syscall_seek(struct registers *regs) {
	int fd = regs->rdi;
	off_t offset = regs->rsi;
	int whence = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] seek: fd {%x}, offset {%x}, whence {%x}\n", CORE_LOCAL->pid, fd, offset, whence);
#endif

	regs->rax = fd_seek(fd, offset, whence);
}

void syscall_openat(struct registers *regs) {
	int dirfd = regs->rdi;
	const char *pathname = (const char*)regs->rsi;
	int flags = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] open: dirfd {%x}, pathname {%s}, flags {%x}\n", CORE_LOCAL->pid, dirfd, pathname, flags);
#endif

	regs->rax = fd_openat(dirfd, pathname, flags);
}

void syscall_close(struct registers *regs) {
	int fd = regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] close: fd {%x}\n", CORE_LOCAL->pid, fd);
#endif

	regs->rax = fd_close(fd);
}

void syscall_fcntl(struct registers *regs) {
#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] fcntl: fd {%x}, cmd {%x}\n", CORE_LOCAL->pid, regs->rdi, regs->rsi);
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
			regs->rax = fd_handle->flags;
			break;
		case F_SETFD:
			fd_handle->flags = regs->rdx;
			regs->rax = 0;
			break;
		case F_GETFL:
			regs->rax = fd_handle->file_handle->flags;
			break;
		case F_SETFL: {
			if (regs->rdx & O_ACCMODE) {
				// It is disallowed to change the access mode.
				set_errno(EINVAL);
				regs->rax = -1;
				break;
			}
			fd_handle->file_handle->flags = regs->rdx;
			regs->rax = 0;
			break;
		}
		default:
			print("fnctl unknown command %x\n", regs->rsi);
			set_errno(EINVAL);
			regs->rax = -1;
	}
}

void syscall_readdir(struct registers *regs) {
	int fd = regs->rdi;
	struct dirent *buf = (void*)regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] readdir: fd {%x}, buf {%x}\n", CORE_LOCAL->pid, fd, (uintptr_t)buf);
#endif

	struct fd_handle *dir_handle = fd_translate(fd);
	if(dir_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct vfs_node *dir = dir_handle->file_handle->vfs_node;

	if(!S_ISDIR(dir->asset->stat->st_mode)) {
		set_errno(ENOTDIR);
		regs->rax = -1;
		return;
	}

	if(!dir_handle->file_handle->dirent_list.length) {
		for(size_t i = 0; i < dir->children.length; i++) {
			struct vfs_node *node = dir->children.data[i];

			struct dirent *entry = alloc(sizeof(struct dirent));

			strcpy(entry->d_name, node->name);
			entry->d_ino = node->asset->stat->st_ino;
			entry->d_off = 0;
			entry->d_reclen = sizeof(struct dirent);

			switch(node->asset->stat->st_mode & S_IFMT) {
				case S_IFCHR:
					entry->d_type = DT_CHR;
					break;
				case S_IFBLK:
					entry->d_type = DT_BLK;
					break;
				case S_IFDIR:
					entry->d_type = DT_DIR;
					break;
				case S_IFLNK:
					entry->d_type = DT_LNK;
					break;
				case S_IFIFO:
					entry->d_type = DT_FIFO;
					break;
				case S_IFREG:
					entry->d_type = DT_REG;
					break;
				case S_IFSOCK:
					entry->d_type = DT_SOCK;
					break;
				default:
					entry->d_type = DT_UNKNOWN;
			}

			VECTOR_PUSH(dir_handle->file_handle->dirent_list, entry);
		}
	}

	if(dir_handle->file_handle->current_dirent >= dir_handle->file_handle->dirent_list.length) {
		set_errno(0);
		regs->rax = -1;
		return;
	}

	*buf = *dir_handle->file_handle->dirent_list.data[dir_handle->file_handle->current_dirent];
	dir_handle->file_handle->current_dirent++;

	regs->rax = 0;
}

void syscall_getcwd(struct registers *regs) {
	char *buf = (void*)regs->rdi;
	size_t size = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] getcwd: buf {%x}, size {%x}\n", CORE_LOCAL->pid, buf, size);
#endif

	const char *path = vfs_absolute_path(CURRENT_TASK->cwd);
	if(strlen(path) <= size) {
		memcpy8((void*)buf, (void*)path, strlen(path));
	} else {
		set_errno(ERANGE);
		regs->rax = 0;
		return;
	}

	regs->rax = (uintptr_t)buf;
}

void syscall_chdir(struct registers *regs) {
	const char *path = (const char*)regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] chdir: path {%s}\n", CORE_LOCAL->pid, path);
#endif

	struct vfs_node *vfs_node = vfs_search_absolute(NULL, path, true);
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		regs->rax = -1;
		return;
	}

	CURRENT_TASK->cwd = vfs_node;

	regs->rax = 0;
}

void syscall_pipe(struct registers *regs) {
	int *fd_pair = (int*)regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] pipe: fd pair {%x}\n", CORE_LOCAL->pid, fd_pair);
#endif

	fd_pair[0] = bitmap_alloc(&CURRENT_TASK->fd_bitmap);
	fd_pair[1] = bitmap_alloc(&CURRENT_TASK->fd_bitmap);

	struct fd_handle *read_fd_handle = alloc(sizeof(struct fd_handle));
	struct fd_handle *write_fd_handle = alloc(sizeof(struct fd_handle));
	struct file_handle *read_file_handle = alloc(sizeof(struct file_handle));
	struct file_handle *write_file_handle = alloc(sizeof(struct file_handle));

	fd_init(read_fd_handle);
	fd_init(write_fd_handle);
	file_init(read_file_handle);
	file_init(write_file_handle);

	struct pipe *pipe = alloc(sizeof(struct pipe));
	*pipe = (struct pipe) {
		.read = read_file_handle,
		.write = write_file_handle,
		.buffer = (void*)(pmm_alloc(DIV_ROUNDUP(PIPE_BUFFER_SIZE, PAGE_SIZE), 1) + HIGH_VMA)
	};

	struct asset *read_asset = alloc(sizeof(struct asset));
	asset_init(read_asset);
	read_asset->read = pipe_read;

	struct asset *write_asset = alloc(sizeof(struct asset));
	asset_init(write_asset);
	write_asset->write = pipe_write;

	struct stat *pipe_stat = alloc(sizeof(struct stat));
	pipe_stat->st_atim = clock_realtime;
	pipe_stat->st_mtim = clock_realtime;
	pipe_stat->st_ctim = clock_realtime;
	pipe_stat->st_mode = S_IFIFO | S_IWUSR;

	// Do we want to support full duplex pipes? If so,
	// make both ends readable and writable.
	read_fd_handle->fd_number = fd_pair[0];
	read_fd_handle->file_handle = read_file_handle;
	read_file_handle->asset = read_asset;
	read_file_handle->pipe = pipe;
	read_file_handle->flags = O_RDONLY;

	write_fd_handle->fd_number = fd_pair[1];
	write_fd_handle->file_handle = write_file_handle;
	write_file_handle->asset = write_asset;
	write_file_handle->pipe = pipe;
	write_file_handle->flags = O_WRONLY;

	read_asset->stat = pipe_stat;
	write_asset->stat = pipe_stat;

	hash_table_push(&CURRENT_TASK->fd_list, &read_fd_handle->fd_number, read_fd_handle, sizeof(read_fd_handle->fd_number));
	hash_table_push(&CURRENT_TASK->fd_list, &write_fd_handle->fd_number, write_fd_handle, sizeof(write_fd_handle->fd_number));

	regs->rax = 0;
}

void syscall_faccessat(struct registers *regs) {
	int dirfd = regs->rdi;
	const char *path = (const char*)regs->rsi;
	int mode = regs->rdx;
	int flags = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] faccessat: dirfd {%x}, path {%s}, mode {%x}, flags {%x}\n", CORE_LOCAL->pid, dirfd, path, mode, flags);
#endif

	int relative = *path == '/' ? 0 : 1;
	struct vfs_node *dir;

	if(!relative) {
		dir = vfs_root;
	} else {
		if(dirfd == AT_FDCWD) {
			dir = CURRENT_TASK->cwd;
		} else {
			struct fd_handle *fd_handle = fd_translate(dirfd);
			if(fd_handle == NULL) {
				set_errno(EBADF);
				regs->rax = -1;
				return;
			}

			if(!S_ISDIR(fd_handle->file_handle->asset->stat->st_mode)) {
				set_errno(EBADF);
				regs->rax = -1;
				return;
			}

			dir = fd_handle->file_handle->vfs_node;
		}
	}

	struct vfs_node *vfs_node = vfs_search_absolute(dir, path, true);
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		regs->rax = -1;
		return;
	}

	// TODO actually check permissions

	regs->rax = 0;
}

void syscall_symlinkat(struct registers *regs) {
	const char *target = (const char*)regs->rdi;
	int newdirfd = regs->rsi;
	const char *linkpath = (const char*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] symlink: target {%s}, newdirfd {%x}, linkpath {%s}\n", CORE_LOCAL->pid, target, newdirfd, linkpath);
#endif

	struct vfs_node *link_node;

	int relative = *linkpath == '/' ? 0 : 1;
	if(relative) {
		if(newdirfd == AT_FDCWD) {
			link_node = vfs_search_absolute(CURRENT_TASK->cwd, linkpath, true);
		} else {
			struct fd_handle *fd_handle = fd_translate(newdirfd);
			if(fd_handle == NULL) {
				set_errno(EBADF);
				regs->rax = -1;
				return;
			}

			link_node = fd_handle->file_handle->vfs_node;
		}
	} else {
		link_node = vfs_search_absolute(NULL, linkpath, true);
	}

	if(link_node->symlink) {
		set_errno(EEXIST);
		regs->rax = -1;
		return;
	}

	char *path = alloc(strlen(target));
	strcpy(path, target);

	link_node->symlink = path;

	regs->rax = 0;
}

void syscall_ioctl(struct registers *regs) {
	int fd = regs->rdi;
	uint64_t req = regs->rsi;
	void *args = (void*)regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] ioctl: fd {%x}, req {%x}, args {%x}\n", CORE_LOCAL->pid, fd, req, args);
#endif

	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	if(fd_handle->file_handle->asset->ioctl == NULL) {
		set_errno(ENOTTY);
		regs->rax = -1;
		return;
	}

	regs->rax = fd_handle->file_handle->asset->ioctl(fd_handle->file_handle->asset, fd, req, args);
}
