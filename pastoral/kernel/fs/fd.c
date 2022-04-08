#include <fs/fd.h>
#include <vector.h>
#include <cpu.h>
#include <sched/sched.h>
#include <errno.h>
#include <bitmap.h>
#include <string.h>
#include <fs/vfs.h>

static char fd_lock;

struct fd_handle *fd_translate(int index) {
	spinlock(&fd_lock);

	struct sched_task *current_task = CURRENT_TASK;
	if(current_task == NULL) {
		return NULL;
	}

	for(size_t i = 0; i < current_task->fd_list.element_cnt; i++) {
		if(current_task->fd_list.elements[i]->fd_number == index) {
			spinrelease(&fd_lock);
			return current_task->fd_list.elements[i];
		}
	}

	spinrelease(&fd_lock);

	return NULL;
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
	if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	if(flags & O_CREAT && vfs_node == NULL) {
		// TODO create
	} else if(vfs_node == NULL) {
		set_errno(ENOENT);
		return -1;
	}

	struct fd_handle *new_handle = alloc(sizeof(struct fd_handle));

	*new_handle = (struct fd_handle) {
		.asset = NULL,
		.fd_number = bitmap_alloc(&CURRENT_TASK->fd_bitmap),
		.flags = flags,
		.position = 0
	};

	VECTOR_PUSH(CURRENT_TASK->fd_list, new_handle);

	return new_handle->fd_number;
}
