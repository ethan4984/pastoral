#include <fs/ramfs.h>
#include <fs/vfs.h>
#include <hash.h>
#include <vector.h>
#include <cpu.h>
#include <time.h>
#include <string.h>
#include <errno.h>

struct hash_table ramfs_node_list;


static struct vfs_node *ramfs_create(struct vfs_node *parent, const char *name, struct stat *stat);
static int ramfs_truncate(struct vfs_node *node, off_t cnt);
static ssize_t ramfs_read(struct file_handle *file, void *buf, size_t cnt, off_t offset);
static ssize_t ramfs_write(struct file_handle *file, const void *buf, size_t cnt, off_t offset);


struct filesystem ramfs_filesystem = {
	.create = ramfs_create,
	.truncate = ramfs_truncate
};


struct file_ops ramfs_fops = {
	.read = ramfs_read,
	.write = ramfs_write
};

size_t ramfs_inode_cnt;
char ramfs_lock;

struct vfs_node *ramfs_create(struct vfs_node *parent, const char *name, struct stat *stat) {

	stat->st_ino = ramfs_inode_cnt++;
	stat->st_blksize = 512;
	stat->st_nlink = 1;

	struct ramfs_handle *ramfs_handle = alloc(sizeof(struct ramfs_handle));
	ramfs_handle->inode = stat->st_ino;

	spinlock(&ramfs_lock);
	hash_table_push(&ramfs_node_list, &ramfs_handle->inode, ramfs_handle, sizeof(ramfs_handle->inode));
	spinrelease(&ramfs_lock);

	struct vfs_node *vfs_node = vfs_create_node(parent, &ramfs_fops, &ramfs_filesystem, stat, name, 0);

	return vfs_node;
}

ssize_t ramfs_read(struct file_handle *file, void *buf, size_t cnt, off_t offset) {
	node_lock(file->vfs_node);
	struct stat *stat = file->stat;

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

	if(ramfs_handle == NULL) {
		node_unlock(file->vfs_node);
		return 0;
	}

	if(offset > stat->st_size) {
		node_unlock(file->vfs_node);
		return 0;
	}

	if(offset + cnt > stat->st_size) {
		cnt = stat->st_size - offset;
	}

	memcpy8(buf, ramfs_handle->buffer + offset, cnt);

	node_unlock(file->vfs_node);
	return cnt;
}

ssize_t ramfs_write(struct file_handle *file, const void *buf, size_t cnt, off_t offset) {
	node_lock(file->vfs_node);
	struct stat *stat = file->stat;

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

	if(ramfs_handle == NULL) {
		node_unlock(file->vfs_node);
		return 0;
	}

	if(offset + cnt > stat->st_size) {
		//stat->st_size += offset + cnt - stat->st_size;
		stat->st_size = offset + cnt;
		ramfs_handle->buffer = realloc(ramfs_handle->buffer, stat->st_size);
	}

	memcpy8(ramfs_handle->buffer + offset, buf, cnt);

	node_unlock(file->vfs_node);
	return cnt;
}

int ramfs_truncate(struct vfs_node *node, off_t cnt) {
	node_lock(node);
	struct stat *stat = node->stat;

	spinlock(&ramfs_lock);
	struct ramfs_handle *ramfs_handle = hash_table_search(&ramfs_node_list, &stat->st_ino, sizeof(stat->st_ino));
	spinrelease(&ramfs_lock);

	if(ramfs_handle == NULL) {
		node_unlock(node);
		return -1;
	}

	stat->st_size = cnt;
	ramfs_handle->buffer = realloc(ramfs_handle->buffer, stat->st_size);

	node_unlock(node);
	return 0;
}
