#include <fs/ramfs.h>
#include <fs/vfs.h>
#include <hash.h>
#include <vector.h>
#include <cpu.h>
#include <time.h>
#include <string.h>
#include <errno.h>

struct hash_table ramfs_node_list;

struct filesystem ramfs_filesystem = {
	.create = ramfs_create
};

size_t ramfs_inode_cnt;
char ramfs_lock;

struct vfs_node *ramfs_create(struct vfs_node *parent, const char *name, int mode) {
	struct asset *asset = vfs_default_asset(mode);

	asset->read = ramfs_read;
	asset->write = ramfs_write;
	asset->resize = ramfs_resize;

	asset->stat->st_ino = ramfs_inode_cnt++;
	asset->stat->st_blksize = 512;
	asset->stat->st_nlink = 1;
	asset->stat->st_mode = mode;
	
	asset->stat->st_atim = clock_realtime;
	asset->stat->st_mtim = clock_realtime;
	asset->stat->st_ctim = clock_realtime;

	struct ramfs_handle *ramfs_handle = alloc(sizeof(struct ramfs_handle));
	ramfs_handle->inode = asset->stat->st_ino;

	spinlock(&ramfs_lock);
	hash_table_push(&ramfs_node_list, &ramfs_handle->inode, ramfs_handle, sizeof(ramfs_handle->inode));
	spinrelease(&ramfs_lock);

	struct vfs_node *vfs_node = vfs_create_node(parent, asset, parent->filesystem, name, 0);

	return vfs_node;
}

ssize_t ramfs_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

	if(ramfs_handle == NULL) {
		spinrelease(&asset->lock);
		return 0;
	}

	if(offset > stat->st_size) {
		spinrelease(&asset->lock);
		return 0;
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

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

	if(ramfs_handle == NULL) {
		spinrelease(&asset->lock);
		return 0;
	}

	stat->st_atim = clock_realtime;
	stat->st_mtim = clock_realtime;
	stat->st_ctim = clock_realtime;

	if(offset + cnt > stat->st_size) {
		//stat->st_size += offset + cnt - stat->st_size;
		stat->st_size = offset + cnt;
		ramfs_handle->buffer = realloc(ramfs_handle->buffer, stat->st_size);
	}
	
	memcpy8(ramfs_handle->buffer + offset, buf, cnt);

	spinrelease(&asset->lock);

	return cnt;
}

int ramfs_resize(struct asset *asset, void*, off_t cnt) {
	spinlock(&asset->lock);

	struct stat *stat = asset->stat;

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

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
