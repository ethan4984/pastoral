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

	ssize_t ret;
	if(S_ISFIFO(stat->st_mode) && fd_handle->pipe) {
		ret = asset->write(asset, fd_handle->pipe, fd_handle->position, count, buf);
	} else {
		ret = asset->write(asset, NULL, fd_handle->position, count, buf);
	}

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

	ssize_t ret;
	if(S_ISFIFO(stat->st_mode) && fd_handle->pipe) {
		ret = asset->read(asset, fd_handle->pipe, fd_handle->position, count, buf);
	} else {
		ret = asset->read(asset, NULL, fd_handle->position, count, buf);
	}

	if(ret != -1) {
		fd_handle->position += ret;
	}

	return ret;
}

ssize_t pipe_read(struct asset *asset, void *out, off_t offset, off_t cnt, void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	if(offset > stat->st_size) {
		// POLL (more like event await dequeue thread)
	}
	
	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		cnt = stat->st_size - offset; 
	}

	memcpy8(buf + offset, out, cnt);

	spinrelease(&asset->lock);

	return cnt;
}

ssize_t pipe_write(struct asset *asset, void *out, off_t offset, off_t cnt, void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	if(offset > stat->st_size) {
		// POLL (more like event await dequeue thread)
	}
	
	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		cnt = stat->st_size - offset; 
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

			dir = fd_handle->vfs_node;
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

		asset->read = parent->asset->read;
		asset->write = parent->asset->write;
		asset->ioctl = parent->asset->ioctl;
		asset->resize = parent->asset->resize;
		asset->stat = stat;

		stat->st_atim = clock_realtime;
		stat->st_mtim = clock_realtime;
		stat->st_ctim = clock_realtime;

		vfs_node = vfs_create_node_deep(parent, asset, parent->filesystem, path);
	} else if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	} else if(flags & O_CREAT && flags & O_EXEC) {
		set_errno(EEXIST);
		return -1;
	}

	struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));

	*new_handle = (struct fd_handle) {
		.asset = vfs_node->asset,
		.vfs_node = vfs_node,
		.fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap),
		.flags = flags,
		.position = 0,
		.dirent_list = { 0 },
		.current_dirent = 0
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

		vfs_node = fd_handle->vfs_node;
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

				if(!S_ISDIR(fd_handle->asset->stat->st_mode)) {
					set_errno(EBADF);
					return -1;
				}

				dir = fd_handle->vfs_node;
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

void syscall_openat(struct registers *regs) {
	int dirfd = regs->rdi;
	const char *pathname = (const char*)regs->rsi;
	int flags = regs->rdx;

#ifndef SYSCALL_DEBUG
	print("syscall: open: dirfd {%x}, pathname {%s}, flags {%x}\n", dirfd, pathname, flags);
#endif

	regs->rax = fd_openat(dirfd, pathname, flags); 
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

void syscall_readdir(struct registers *regs) {
	int fd = regs->rdi;
	struct dirent *buf = (void*)regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: readdir: fd {%x}, buf {%x}\n", fd, (uintptr_t)buf);
#endif

	struct fd_handle *dir_handle = fd_translate(fd);
	if(dir_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	struct vfs_node *dir = dir_handle->vfs_node;

	if(!S_ISDIR(dir->asset->stat->st_mode)) {
		set_errno(ENOTDIR);
		regs->rax = -1;
		return;
	}

	if(!dir_handle->dirent_list.length) {
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

			VECTOR_PUSH(dir_handle->dirent_list, entry);
		}
	}

	if(dir_handle->current_dirent >= dir_handle->dirent_list.length) {
		set_errno(0);
		regs->rax = -1;
		return;
	}

	*buf = *dir_handle->dirent_list.data[dir_handle->current_dirent];
	dir_handle->current_dirent++;

	regs->rax = 0;
}

void syscall_getcwd(struct registers *regs) {
	char *buf = (void*)regs->rdi;
	size_t size = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: getcwd: buf {%x}, size {%x}\n", buf, size);
#endif

	const char *path = vfs_absolute_path(CURRENT_TASK->cwd);
	if(strlen(path) <= size) {
	print("homo?\n");
		memcpy8((void*)buf, (void*)path, strlen(path));
	} else {
	print("amog?\n");
		set_errno(ERANGE);
		regs->rax = 0;
		return; 
	} 
	print("sex?\n");

	regs->rax = (uintptr_t)buf;
}

void syscall_chdir(struct registers *regs) { 
	const char *path = (const char*)regs->rdi;

#ifndef SYSCALL_DEBUG
	print("syscall: chdir: path {%s}\n", path);
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
	print("syscall: pipe: fd pair {%x}\n", fd_pair);
#endif

	fd_pair[0] = bitmap_alloc(&CURRENT_TASK->fd_bitmap);
	fd_pair[1] = bitmap_alloc(&CURRENT_TASK->fd_bitmap);

	struct fd_handle *read_handle = alloc(sizeof(struct fd_handle));
	struct fd_handle *write_handle = alloc(sizeof(struct fd_handle));

	struct pipe *pipe = alloc(sizeof(struct pipe));
	*pipe = (struct pipe) {
		.read = read_handle,
		.write = write_handle,
		.fd_pair[0] = fd_pair[0], 
		.fd_pair[1] = fd_pair[1]
	};

	struct asset *read_asset = alloc(sizeof(struct asset));
	struct stat *read_stat = alloc(sizeof(struct stat));
	read_asset->stat = read_stat;

	read_stat->st_atim = clock_realtime;
	read_stat->st_mtim = clock_realtime;
	read_stat->st_ctim = clock_realtime;

	read_stat->st_mode = S_IFIFO | S_IRUSR;

	struct asset *write_asset = alloc(sizeof(struct asset));
	struct stat *write_stat = alloc(sizeof(struct stat));
	write_asset->stat = write_stat;

	write_stat->st_atim = clock_realtime;
	write_stat->st_mtim = clock_realtime;
	write_stat->st_ctim = clock_realtime;

	read_stat->st_mode = S_IFIFO | S_IWUSR;

	read_handle->pipe = pipe;
	read_handle->asset = read_asset; 
	read_handle->fd_number = fd_pair[0];

	write_handle->pipe = pipe;
	write_handle->asset = write_asset;
	write_handle->fd_number = fd_pair[1];

	hash_table_push(&CURRENT_TASK->fd_list, &read_handle->fd_number, read_handle, sizeof(read_handle->fd_number));
	hash_table_push(&CURRENT_TASK->fd_list, &write_handle->fd_number, read_handle, sizeof(write_handle->fd_number));

	regs->rax = 0;
}

void syscall_faccessat(struct registers *regs) {
	int dirfd = regs->rdi; 
	const char *path = (const char*)regs->rsi;
	int mode = regs->rdx;
	int flags = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: faccessat: dirfd {%x}, path {%s}, mode {%x}, flags {%x}\n", dirfd, path, mode, flags);
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

			if(!S_ISDIR(fd_handle->asset->stat->st_mode)) {
				set_errno(EBADF);
				regs->rax = -1;
				return;
			}

			dir = fd_handle->vfs_node;
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
	print("syscall: symlink: target {%s}, newdirfd {%x}, linkpath {%s}\n", target, newdirfd, linkpath);
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

			link_node = fd_handle->vfs_node;
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
