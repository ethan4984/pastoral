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


static int user_dir_lookup(int dirfd, const char *path, struct vfs_node **ret) {
	bool relative = *path != '/' ? true : false;

	if(relative) {
		if(dirfd == AT_FDCWD) {
			*ret = CURRENT_TASK->cwd;
		} else {
			struct fd_handle *dir_handle = fd_translate(dirfd);
			if(dir_handle == NULL) {
				set_errno(EBADF);
				return -1;
			}
			*ret = dir_handle->file_handle->vfs_node;
		}
	} else {
		*ret = vfs_root;
	}

	if(*ret == NULL) {
		*ret = vfs_root;
	}

	return 0;
}


static int user_lookup_at(int dirfd, const char *path, int lookup_flags, mode_t mode, struct vfs_node **ret) {
	if(*path == '/' && *(path + 1) == '\0') {
		*ret = vfs_root;
		return 0;
	}

	struct vfs_node *parent;
	if(user_dir_lookup(dirfd, path, &parent) == -1) {
		return -1;
	}

	bool symlink_follow = lookup_flags & AT_SYMLINK_NOFOLLOW ? true : false;
	bool effective_ids = lookup_flags & AT_EACCESS ? true : false;

	VECTOR(const char*) subpath_list = { 0 };

	char *str = alloc(strlen(path));
	strcpy(str, path);

	while(*str == '/') *str++ = 0;

	while(*str) {
		const char *subpath = str;

		while(*str && *str != '/') str++;
		while(*str == '/') *str++ = 0;

		VECTOR_PUSH(subpath_list, subpath);
	}

	size_t i = 0;
	for(; i < (subpath_list.length - 1); i++) {
		if(stat_has_access(parent->asset->stat, CURRENT_TASK->effective_uid, CURRENT_TASK->effective_gid, X_OK) == -1) {
			set_errno(EACCES);
			return -1;
		}

		parent = vfs_search_relative(parent, subpath_list.data[i], true);
		if(parent == NULL) {
			set_errno(ENOENT);
			return -1;
		}

		if(parent->mountpoint) {
			parent = parent->mountpoint;
		}
	}

	if(stat_has_access(parent->asset->stat, CURRENT_TASK->effective_uid, CURRENT_TASK->effective_gid, X_OK) == -1) {
		set_errno(EACCES);
		return -1;
	}

	struct vfs_node *vfs_node = vfs_search_relative(parent, subpath_list.data[i], symlink_follow);
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	uid_t uid = effective_ids ? CURRENT_TASK->effective_uid : CURRENT_TASK->real_uid;
	gid_t gid = effective_ids ? CURRENT_TASK->effective_gid : CURRENT_TASK->real_gid;

	struct stat *stat = vfs_node->asset->stat;

	if(stat_has_access(stat, uid, gid, mode) == -1) {
		set_errno(EACCES);
		return -1;
	}

	*ret = vfs_node;
	return 0;
}

int stat_has_access(struct stat *stat, uid_t uid, gid_t gid, int mode) {
	if(uid == 0) {
		return 0;
	}

	mode_t mask_uid = 0, mask_gid = 0, mask_oth = 0;

	if(mode & R_OK) { mask_uid |= S_IRUSR; mask_gid |= S_IRGRP; mask_oth |= S_IROTH; }
	if(mode & W_OK) { mask_uid |= S_IWUSR; mask_gid |= S_IWGRP; mask_oth |= S_IWOTH; }
	if(mode & X_OK) { mask_uid |= S_IXUSR; mask_gid |= S_IXGRP; mask_oth |= S_IXOTH; }

	if(stat->st_uid == uid) {
		if((stat->st_mode & mask_uid) == mask_uid) {
			return 0;
		}
		return -1;
	} else if(stat->st_gid == gid) {
		if((stat->st_mode & mask_gid) == mask_gid) {
			return 0;
		}
		return -1;
	} else {
		if((stat->st_mode & mask_oth) == mask_oth) {
			return 0;
		}
		return -1;
	}

}

static struct fd_handle *fd_translate_unlocked(int index) {
	struct sched_task *current_task = CURRENT_TASK;
	return hash_table_search(&current_task->fd_list, &index, sizeof(index));
}

struct fd_handle *fd_translate(int index) {
	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		return NULL;
	}

	spinlock(&current_task->fd_lock);
	struct fd_handle *handle = fd_translate_unlocked(index);
	spinrelease(&current_task->fd_lock);

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

	file_lock(fd_handle->file_handle);
	struct asset *asset = fd_handle->file_handle->asset;
	struct stat *stat = asset->stat;

	if(asset->write == NULL) {
		file_unlock(fd_handle->file_handle);
		set_errno(EINVAL);
		return -1;
	}

	if((fd_handle->file_handle->flags & O_ACCMODE) != O_WRONLY
		&& (fd_handle->file_handle->flags & O_ACCMODE) != O_RDWR) {
		file_unlock(fd_handle->file_handle);
		set_errno(EBADF);
		return -1;
	}

	ssize_t ret;
	if(S_ISFIFO(stat->st_mode) && fd_handle->file_handle->pipe) {
		ret = asset->write(asset, fd_handle->file_handle->pipe->buffer, fd_handle->file_handle->position, count, buf);
	} else {
		if (fd_handle->file_handle->flags & O_APPEND) {
			fd_handle->file_handle->position = stat->st_size;
		}
		ret = asset->write(asset, NULL, fd_handle->file_handle->position, count, buf);
	}

	if(ret != -1) {
		fd_handle->file_handle->position += ret;
	}

	file_unlock(fd_handle->file_handle);
	return ret;
}

ssize_t fd_read(int fd, void *buf, size_t count) {
	struct fd_handle *fd_handle = fd_translate(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	file_lock(fd_handle->file_handle);
	struct stat *stat = fd_handle->file_handle->asset->stat;
	if(S_ISDIR(stat->st_mode)) {
		file_unlock(fd_handle->file_handle);
		set_errno(EISDIR);
		return -1;
	}

	struct asset *asset = fd_handle->file_handle->asset;

	if(asset->read == NULL) {
		file_unlock(fd_handle->file_handle);
		set_errno(EINVAL);
		return -1;
	}

	if((fd_handle->file_handle->flags & O_ACCMODE) != O_RDONLY
		&& (fd_handle->file_handle->flags & O_ACCMODE) != O_RDWR) {
		file_unlock(fd_handle->file_handle);
		set_errno(EBADF);
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

	file_unlock(fd_handle->file_handle);
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

int fd_openat(int dirfd, const char *path, int flags, mode_t mode) {
	if(strlen(path) > MAX_PATH_LENGTH) {
		set_errno(ENAMETOOLONG);
		return -1;
	}

	mode &= (S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX | S_ISUID | S_ISGID);
	if((flags & O_ACCMODE) == 0)
		flags |= O_RDONLY;

	int access_mode = 0;
	if((flags & O_ACCMODE) == O_RDONLY) {
		access_mode = R_OK;
	} else if((flags & O_ACCMODE) == O_WRONLY) {
		access_mode = W_OK;
	} else if((flags & O_ACCMODE) == O_RDWR) {
		access_mode = R_OK | W_OK;
	} else {
		set_errno(EINVAL);
		return -1;
	}

	if((flags & O_TRUNC) && !(access_mode & W_OK)) {
		set_errno(EINVAL);
		return -1;
	}

	struct vfs_node *dir;
	if(user_dir_lookup(dirfd, path, &dir) == -1) {
		return -1;
	}

	struct vfs_node *vfs_node = vfs_search_absolute(dir, path, true);

	if(flags & O_CREAT && vfs_node == NULL) {
		struct vfs_node *parent = dir;

		if(stat_has_access(parent->asset->stat, CURRENT_TASK->effective_uid, CURRENT_TASK->effective_gid, W_OK | X_OK) == -1) {
			set_errno(EACCES);
			return -1;
		}

		char *name = alloc(strlen(path + find_last_char(path, '/')) + 1);
		strcpy(name, path + find_last_char(path, '/'));

		vfs_node = parent->filesystem->create(parent, name, S_IFREG | (mode & ~(CURRENT_TASK->umask)));
		vfs_node->asset->stat->st_uid = CURRENT_TASK->effective_uid;

		// Behave like Linux and Solaris. If the SGID bit of the parent directory is set,
		// the group of the new file is going to be the GID of the parent directory.
		// Otherwise, it's going to be the effective GID.
		if(parent->asset->stat->st_mode & S_ISGID)
			vfs_node->asset->stat->st_gid = parent->asset->stat->st_gid;
		else
			vfs_node->asset->stat->st_uid = CURRENT_TASK->effective_gid;
	} else if((flags & O_CREAT) && (flags & O_EXCL)) {
		set_errno(EEXIST);
		return -1;
	} else if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	if(!(flags & O_DIRECTORY) && S_ISDIR(vfs_node->asset->stat->st_mode)) {
		set_errno(EISDIR);
		return -1;
	}

	if(stat_has_access(vfs_node->asset->stat, CURRENT_TASK->effective_uid, CURRENT_TASK->effective_gid, access_mode) == -1) {
		set_errno(EACCES);
		return -1;
	}

	if(flags & O_TRUNC)
		vfs_node->asset->resize(vfs_node->asset, NULL, 0);

	struct fd_handle *new_fd_handle = alloc(sizeof(struct fd_handle));
	struct file_handle *new_file_handle = alloc(sizeof(struct file_handle));

	fd_init(new_fd_handle);
	file_init(new_file_handle);

	new_fd_handle->fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap);
	new_fd_handle->file_handle = new_file_handle;
	new_fd_handle->flags = (flags & O_CLOEXEC) ? FD_CLOEXEC : 0;

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


static void fd_close_unlocked(struct fd_handle *handle) {
	struct sched_task *current_task = CURRENT_TASK;
	file_put(handle->file_handle);
	hash_table_delete(&current_task->fd_list, &handle->fd_number, sizeof(handle->fd_number));
	bitmap_free(&current_task->fd_bitmap, handle->fd_number);
	free(handle);
}


int fd_close(int fd) {
	struct sched_task *current_task = CURRENT_TASK;

	spinlock(&current_task->fd_lock);
	struct fd_handle *fd_handle = fd_translate_unlocked(fd);
	if(fd_handle == NULL) {
		spinrelease(&current_task->fd_lock);
		set_errno(EBADF);
		return -1;
	}

	if(current_task == NULL) {
		spinrelease(&current_task->fd_lock);
		set_errno(ENOENT);
		return -1;
	}

	fd_close_unlocked(fd_handle);
	spinrelease(&current_task->fd_lock);

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

int fd_dup(int fd, bool clear_cloexec) {
	struct sched_task *current_task = CURRENT_TASK;
	spinlock(&current_task->fd_lock);

	struct fd_handle *fd_handle = fd_translate_unlocked(fd);
	if(fd_handle == NULL) {
		spinrelease(&current_task->fd_lock);
		set_errno(EBADF);
		return -1;
	}

	struct fd_handle *handle = alloc(sizeof(struct fd_handle));
	*handle = *fd_handle;
	handle->fd_number = bitmap_alloc(&current_task->fd_bitmap);

	if (clear_cloexec)
		handle->flags &= ~FD_CLOEXEC;
	else
		handle->flags |= FD_CLOEXEC;

	file_get(handle->file_handle);
	hash_table_push(&current_task->fd_list, &handle->fd_number, handle, sizeof(handle->fd_number));
	spinrelease(&current_task->fd_lock);

	return handle->fd_number;
}

int fd_dup2(int oldfd, int newfd) {
	struct sched_task *current_task = CURRENT_TASK;
	spinlock(&current_task->fd_lock);

	struct fd_handle *oldfd_handle = fd_translate_unlocked(oldfd), *new_handle;;
	if(oldfd_handle == NULL) {
		spinrelease(&current_task->fd_lock);
		set_errno(EBADF);
		return -1;
	}

	if(oldfd == newfd) {
		spinrelease(&current_task->fd_lock);
		return newfd;
	}

	new_handle = alloc(sizeof(struct fd_handle));
	*new_handle = *oldfd_handle;
	new_handle->fd_number = newfd;
	new_handle->flags &= ~FD_CLOEXEC;
	file_get(new_handle->file_handle);

	if(BIT_TEST(current_task->fd_bitmap.data, newfd)) {
		fd_close_unlocked(fd_translate_unlocked(newfd));
	} else {
		BIT_SET(current_task->fd_bitmap.data, newfd);
	}

	hash_table_push(&current_task->fd_list, &new_handle->fd_number, new_handle, sizeof(new_handle->fd_number));

	spinrelease(&current_task->fd_lock);

	return new_handle->fd_number;
}

int fd_generate_dirent(struct fd_handle *dir_handle, struct vfs_node *node, struct dirent *entry) {
	if(!S_ISDIR(dir_handle->file_handle->asset->stat->st_mode)) {
		set_errno(ENOTDIR);
		return -1;
	}

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

	return 0;
}


int fd_fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag) {
	struct vfs_node *node;

	// Restricted chown: only root may change the owner.
	if(CURRENT_TASK->effective_uid != 0) {
		set_errno(EPERM);
		return -1;
	}

	if(uid == -1 && gid == -1)
		return 0;

	if(!(flag & AT_EMPTY_PATH) && !strlen(path)) {
		set_errno(EINVAL);
		return -1;
	}

	if(flag & AT_EMPTY_PATH) {
		struct fd_handle *handle = fd_translate(fd);
		if(!handle) {
			set_errno(EBADF);
			return -1;
		}

		node = handle->file_handle->vfs_node;
	} else {
		// We are only interested in the node and we are superuser, so with a mode of 0
		// we can get away with it.
		if(user_lookup_at(fd, path, flag & AT_SYMLINK_NOFOLLOW, 0, &node) == -1) {
			return -1;
		}
	}

	if(uid != -1)
		node->asset->stat->st_uid = uid;
	if(gid != -1)
		node->asset->stat->st_gid = gid;

	return 0;
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

	regs->rax = fd_dup(fd, true);
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
	mode_t mode = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] open: dirfd {%x}, pathname {%s}, flags {%x}\n", CORE_LOCAL->pid, dirfd, pathname, flags);
#endif

	regs->rax = fd_openat(dirfd, pathname, flags, mode);
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
	print("syscall: [pid %x] fcntl: fd {%x}, cmd {%x}, data {%x}\n", CORE_LOCAL->pid, regs->rdi, regs->rsi, regs->rdx);
#endif

	struct fd_handle *fd_handle = fd_translate(regs->rdi);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	switch(regs->rsi) {
		case F_DUPFD:
			regs->rax = fd_dup(regs->rdi, true);
			break;
		case F_DUPFD_CLOEXEC:
			regs->rax = fd_dup(regs->rdi, false);
			break;
		case F_GETFD:
			fd_lock(fd_handle);
			regs->rax = fd_handle->flags;
			fd_unlock(fd_handle);
			break;
		case F_SETFD:
			fd_lock(fd_handle);
			fd_handle->flags = regs->rdx;
			regs->rax = 0;
			fd_unlock(fd_handle);
			break;
		case F_GETFL:
			file_lock(fd_handle->file_handle);
			regs->rax = fd_handle->file_handle->flags;
			file_unlock(fd_handle->file_handle);
			break;
		case F_SETFL: {
			if (regs->rdx & O_ACCMODE) {
				// It is disallowed to change the access mode.
				set_errno(EINVAL);
				regs->rax = -1;
				break;
			}
			file_lock(fd_handle->file_handle);
			fd_handle->file_handle->flags = regs->rdx;
			regs->rax = 0;
			file_unlock(fd_handle->file_handle);
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

	if((dir->children.length >= dir_handle->file_handle->current_dirent) && dir->children.length != dir_handle->file_handle->dirent_list.length) {
		VECTOR_CLEAR(dir_handle->file_handle->dirent_list);
		dir_handle->file_handle->current_dirent = 0;
	}

	if(!dir_handle->file_handle->dirent_list.length) {
		for(size_t i = 0; i < dir->children.length; i++) {
			struct vfs_node *node = dir->children.data[i];

			struct dirent *entry = alloc(sizeof(struct dirent));

			int ret = fd_generate_dirent(dir_handle, node, entry);
			if(ret == -1) {
				regs->rax = -1;
				return;
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

	struct vfs_node *node;
	if (user_lookup_at(AT_FDCWD, path, 0, X_OK, &node) == -1) {
		regs->rax = -1;
		return;
	}

	CURRENT_TASK->cwd = node;

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
	read_asset->read = pipe_read;

	struct asset *write_asset = alloc(sizeof(struct asset));
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

	spinlock(&CURRENT_TASK->fd_lock);
	hash_table_push(&CURRENT_TASK->fd_list, &read_fd_handle->fd_number, read_fd_handle, sizeof(read_fd_handle->fd_number));
	hash_table_push(&CURRENT_TASK->fd_list, &write_fd_handle->fd_number, write_fd_handle, sizeof(write_fd_handle->fd_number));
	spinrelease(&CURRENT_TASK->fd_lock);

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

	if (!(mode & F_OK) && !(mode & (R_OK | W_OK | X_OK))) {
		regs->rax = -1;
		return;
	}

	int lookup_flags = 0;

	if(mode == F_OK) mode = 0;
	if(flags & AT_SYMLINK_NOFOLLOW) lookup_flags |= AT_SYMLINK_NOFOLLOW;
	if(flags & AT_EMPTY_PATH) lookup_flags |= AT_EMPTY_PATH;

	struct vfs_node *node;
	if(user_lookup_at(dirfd, path, lookup_flags, mode, &node) == -1) {
		regs->rax = -1;
		return;
	}

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

void syscall_umask(struct registers *regs) {
	mode_t mask = regs->rdi & 0777;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] umask: mask {%x}\n", CORE_LOCAL->pid, mask);
#endif

	regs->rax = CURRENT_TASK->umask;
	CURRENT_TASK->umask = mask;
}

static int stat_chmod(struct stat *stat, mode_t mode) {
	if(CURRENT_TASK->effective_uid != stat->st_uid
		&& CURRENT_TASK->effective_uid != 0) {
		set_errno(EPERM);
		return -1;
	}

	stat->st_mode |= (mode & (
		S_IRWXU | S_IRWXG | S_IRWXO | S_ISUID | S_ISGID | S_ISVTX
	));
	return 0;
}


void syscall_fchmod(struct registers *regs) {
	int fd = regs->rdi;
	mode_t mode = regs->rsi;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] fchmod: fd {%x}, mode {%x}\n", CORE_LOCAL->pid, fd, mode);
#endif

	struct fd_handle *handle = fd_translate(fd);
	if(handle == NULL) {
		set_errno(EBADF);
		regs->rax = -1;
		return;
	}

	regs->rax = stat_chmod(handle->file_handle->asset->stat, mode);
}


void syscall_fchmodat(struct registers *regs) {
	int fd = regs->rdi;
	const char *path = (const char*) regs->rsi;
	mode_t mode = regs->rdx;
	int flags = regs->r10;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] fchmodat: fd {%x}, path {%s}, mode {%x}, flags {%x}\n", CORE_LOCAL->pid, fd, path, mode, flags);
#endif

	struct vfs_node *file;
	user_lookup_at(fd, path, 0, flags, &file);
	if (file == NULL) {
		set_errno(ENOENT);
		regs->rax = -1;
		return;
	}

	regs->rax = stat_chmod(file->asset->stat, mode);
}


void syscall_fchownat(struct registers *regs) {
	int fd = regs->rdi;
	const char *path = (const char*) regs->rsi;
	uid_t uid = regs->rdx;
	gid_t gid = regs->r10;
	int flag = regs->r8;

#ifndef SYSCALL_DEBUG
	print("syscall: [pid %x] fchownat: fd {%x}, path {%s}, uid {%x}, gid {%x}, flag {%x}\n", CORE_LOCAL->pid, fd, path, uid, gid, flag);
#endif

	regs->rax = fd_fchownat(fd, path, uid, gid, flag);
}
