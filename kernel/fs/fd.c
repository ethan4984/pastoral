#include <fs/fd.h>
#include <vector.h>
#include <cpu.h>
#include <sched/sched.h>
#include <errno.h>

static char fd_lock;

struct fd_handle *translate_fd(int index) {
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

off_t lseek(int fd, off_t offset, int whence) {
	struct fd_handle *fd_handle = translate_fd(fd);
	if(fd_handle == NULL) {
		set_errno(EBADF);
		return -1;
	}

	struct stat *stat = fd_handle->vfs_node->asset->stat;
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
