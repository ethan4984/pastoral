#include <fs/ramfs.h>
#include <fs/vfs.h>
#include <vector.h>
#include <cpu.h>
#include <time.h>
#include <string.h>

struct ramfs_handle {
	size_t inode;
	void *buffer;
};

static VECTOR(struct ramfs_handle*) ramfs_node_list;
static size_t inode_cnt;
static char ramfs_lock;

struct ramfs_handle *ramfs_inode2node(size_t inode_number) {
	spinlock(&ramfs_lock);

	for(size_t i = 0; i < ramfs_node_list.element_cnt; i++) {
		if(ramfs_node_list.elements[i]->inode == inode_number) {
			spinrelease(&ramfs_lock);
			return ramfs_node_list.elements[i];
		}
	}

	spinrelease(&ramfs_lock);

	return NULL;
}

struct vfs_node *ramfs_create(struct vfs_node *parent, const char *name, int mode) {
	struct asset *asset = vfs_default_asset(mode);

	asset->read = ramfs_read;
	asset->write = ramfs_write;
	asset->resize = ramfs_resize;

	asset->stat->st_ino = inode_cnt++;
	asset->stat->st_blksize = 512;
	asset->stat->st_nlink = 1;
	asset->stat->st_mode = mode;
	
	asset->stat->st_atim = clock_realtime;
	asset->stat->st_mtim = clock_realtime;
	asset->stat->st_ctim = clock_realtime;

	struct ramfs_handle *ramfs_handle = alloc(sizeof(struct ramfs_handle));
	ramfs_handle->inode = asset->stat->st_ino;
	VECTOR_PUSH(ramfs_node_list, ramfs_handle);

	struct vfs_node *vfs_node = vfs_create_node(parent, asset, parent->filesystem, name);

	return vfs_node;
}

ssize_t ramfs_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	struct ramfs_handle *ramfs_handle = ramfs_inode2node(stat->st_ino);
	if(ramfs_handle == NULL) {
		spinrelease(&asset->lock);
		return -1;
	}

	if(offset > stat->st_size) {
		spinrelease(&asset->lock);
		return -1;
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		cnt = stat->st_size - offset;
	}

	memcpy8(buf, ramfs_handle->buffer + offset, cnt);

	spinrelease(&asset->lock);
	
	return cnt;
}

ssize_t ramfs_write(struct asset *asset, void*, off_t offset, off_t cnt, const void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	struct ramfs_handle *ramfs_handle = ramfs_inode2node(stat->st_ino);
	if(ramfs_handle == NULL) {
		spinrelease(&asset->lock);
		return -1;
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		stat->st_size += offset + cnt - stat->st_size;
		ramfs_handle->buffer = realloc(ramfs_handle->buffer, stat->st_size);
	}
	
	memcpy8(ramfs_handle->buffer + offset, buf, cnt);

	spinrelease(&asset->lock);

	return cnt;
}

int ramfs_resize(struct asset *asset, void*, off_t cnt) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	struct ramfs_handle *ramfs_handle = ramfs_inode2node(stat->st_ino);
	if(ramfs_handle == NULL) {
		spinrelease(&asset->lock);
		return -1;
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	stat->st_size = cnt;
	ramfs_handle->buffer = realloc(ramfs_handle->buffer, stat->st_size);

	spinrelease(&asset->lock);

	return stat->st_size;
}
