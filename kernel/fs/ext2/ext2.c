#include <fs/ext2/ext2.h>
#include <fs/fd.h>
#include <debug.h>

static struct vfs_node *ext2_create(struct vfs_node *parent, const char *name, struct stat *stat);
static int ext2_truncate(struct vfs_node *node, off_t cnt);
static int ext2_refresh(struct vfs_node *dir);
static ssize_t ext2_read(struct file_handle *handle, void *buf, size_t cnt, off_t offset);
static ssize_t ext2_write(struct file_handle *handle, const void *buf, size_t cnt, off_t offset);

static struct file_ops ext2_fops = {
	.read = ext2_read,
	.write = ext2_write,
	.ioctl = NULL,
	.shared = NULL
};

static int ext2_read_inode_entry(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index);
static int ext2_write_inode_entry(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index);
static int ext2_read_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index);
static int ext2_write_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index);
static int ext2_bgd_allocate_inode(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index);
static int ext2_bgd_allocate_block(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index);
static int ext2_allocate_inode(struct ext2_fs *ext2_fs);
static int ext2_allocate_block(struct ext2_fs *ext2_fs);
static int ext2_free_inode(struct ext2_fs *ext2_fs, uint32_t inode);
static int ext2_free_block(struct ext2_fs *ext2_fs, uint32_t block);
static int ext2_inode_read(struct ext2_fs *ext2_fs, struct ext2_inode *inode, void *buffer, size_t cnt, off_t offset);
static int ext2_inode_write(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index, const void *buffer, size_t cnt, off_t offset);
static int ext2_inode_set_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index, uint32_t iblock, uint32_t block);
static int ext2_read_dirents(struct ext2_fs *ext2_fs, struct ext2_inode *inode, struct ext2_file **files);
static int ext2_write_dirent(struct ext2_fs *ext2_fs, struct ext2_inode *dir, int dir_inode, const char *name, int inode, int type);
static int ext2_read_symlink(struct ext2_fs *ext2_fs, struct ext2_inode *inode, char **path);
static int ext2_inode_get_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, uint32_t iblock, uint32_t *block);

static inline uint64_t ext2_inode_read_size(struct ext2_inode *inode) {
	return inode->size32l | ((uint64_t)inode->size32h << 32);
}

static uint64_t ext2_inode_write_size(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index, uint64_t size) {
	inode->size32l = (uint32_t)size;
	inode->size32h = (uint32_t)(size >> 32);

	if(ext2_write_inode_entry(ext2_fs, inode, index) == -1) {
		return -1;
	}

	return 0;
}

static ssize_t ext2_read(struct file_handle *handle, void *buf, size_t cnt, off_t offset) {
	struct ext2_fs *ext2_fs = handle->vfs_node->filesystem->private_data;
	if(ext2_fs == NULL) {
		return -1;
	}

	struct ext2_inode inode;

	if(ext2_read_inode_entry(ext2_fs, &inode, handle->stat->st_ino) == -1) {
		return -1;
	}

	ssize_t bytes_read = ext2_inode_read(ext2_fs, &inode, buf, cnt, offset);

	return bytes_read;
}

static ssize_t ext2_write(struct file_handle *handle, const void *buf, size_t cnt, off_t offset) {
	struct ext2_fs *ext2_fs = handle->vfs_node->filesystem->private_data;
	struct ext2_inode inode;

	if(ext2_read_inode_entry(ext2_fs, &inode, handle->stat->st_ino) == -1) {
		return -1;
	}

	ssize_t bytes_written = ext2_inode_write(ext2_fs, &inode, handle->stat->st_ino, buf, cnt, offset);

	return bytes_written;
}

static int ext2_truncate(struct vfs_node *node, off_t cnt) {
	if(node->stat->st_size == cnt) {
		return 0;
	}

	struct ext2_fs *ext2_fs = node->filesystem->private_data;
	struct ext2_inode inode;

	if(ext2_read_inode_entry(ext2_fs, &inode, node->stat->st_ino) == -1) {
		return -1;
	}

	if(node->stat->st_size > cnt) {
		for(uint32_t iblock = cnt / ext2_fs->block_size; iblock < node->stat->st_size / ext2_fs->block_size; iblock++) {
			uint32_t block;
			if(ext2_inode_get_block(ext2_fs, &inode, iblock, &block) == -1) {
				return -1;
			}

			if(ext2_free_block(ext2_fs, block) == -1) {
				return -1;
			}
		}
	} else {
		for(uint32_t iblock = node->stat->st_size / ext2_fs->block_size; iblock < cnt / ext2_fs->block_size; iblock++) {
			int block = ext2_allocate_block(ext2_fs);
			if(block == -1) {
				return -1;
			}

			if(ext2_inode_set_block(ext2_fs, &inode, node->stat->st_ino, iblock, block) == -1) {
				return -1;
			}
		}
	}

	return 0;
}

static struct vfs_node *ext2_create(struct vfs_node *parent, const char *name, struct stat *stat) {
	struct ext2_fs *ext2_fs = parent->filesystem->private_data;
	struct ext2_inode parent_inode;

	if(ext2_read_inode_entry(ext2_fs, &parent_inode, parent->stat->st_ino) == -1) {
		return NULL;
	}

	stat->st_dev = ext2_fs->partition->cdev->rdev;
	stat->st_ino = ext2_allocate_inode(ext2_fs);
	stat->st_uid = parent_inode.uid;
	stat->st_uid = parent_inode.gid;
	stat->st_size = 0;
	stat->st_blocks = 0;
	stat->st_blksize = ext2_fs->block_size;

	int dir_type;

	if((stat->st_mode & S_IFREG) == S_IFREG) {
		dir_type = 1;
	} else if((stat->st_mode & S_IFDIR) == S_IFDIR) {
		dir_type = 2;
	} else if((stat->st_mode & S_IFCHR) == S_IFCHR) {
		dir_type = 3;
	} else if((stat->st_mode & S_IFBLK) == S_IFBLK) {
		dir_type = 4;
	} else if((stat->st_mode & S_IFIFO) == S_IFIFO) {
		dir_type = 5;
	} else if((stat->st_mode & S_IFSOCK) == S_IFSOCK) {
		dir_type = 6;
	} else if((stat->st_mode & S_IFLNK) == S_IFLNK) {
		dir_type = 7;
	} else {
		print("ext2: warning: unknown st_mode %x\n", stat->st_mode);
		dir_type = 0;
	}

	if(ext2_write_dirent(ext2_fs, &parent_inode, parent->stat->st_ino, name, stat->st_ino, dir_type) == -1) {
		return NULL;
	}

	struct vfs_node *vfs_node = vfs_create_node(parent, &ext2_fops, ext2_fs->filesystem, stat, name, 0);

	return vfs_node;
}

static int ext2_refresh(struct vfs_node *dir) {
	struct ext2_fs *ext2_fs = dir->filesystem->private_data;
	struct ext2_inode dir_inode;

	if(ext2_read_inode_entry(ext2_fs, &dir_inode, dir->stat->st_ino) == -1) {
		return -1;
	}

	struct ext2_file *files = NULL;

	if(ext2_read_dirents(ext2_fs, &dir_inode, &files) == -1) {
		return -1;
	}

	struct ext2_file *file = files;

	while(file) {
		struct ext2_inode inode;
		if(ext2_read_inode_entry(ext2_fs, &inode, file->dirent->inode_index) == -1) {
			return -1;
		}

		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);

		switch(file->dirent->dir_type) {
			case 1:
				stat->st_mode |= S_IFREG;
				break;
			case 2:
				stat->st_mode |= S_IFDIR;
				break;
			case 3:
				stat->st_mode |= S_IFCHR;
				break;
			case 4:
				stat->st_mode |= S_IFBLK;
				break;
			case 5:
				stat->st_mode |= S_IFIFO;
				break;
			case 6:
				stat->st_mode |= S_IFSOCK;
				break;
			case 7:
				stat->st_mode |= S_IFLNK;
				break;
			default:
				print("ext2: warning: unknown dirent type %d on %s\n", file->dirent->dir_type, file->name);
				stat->st_mode = S_IFREG;
		}

		stat->st_uid = inode.uid;
		stat->st_gid = inode.gid;
		stat->st_size = ext2_inode_read_size(&inode);
		stat->st_blksize = ext2_fs->block_size;
		stat->st_blocks = DIV_ROUNDUP(stat->st_size, stat->st_blksize);
		stat->st_ino = file->dirent->inode_index;
		stat->st_nlink = 1;

		struct vfs_node *node = vfs_create_node(dir, &ext2_fops, ext2_fs->filesystem, stat, file->name, 0);
		if(node == NULL) {
			return -1;
		}

		node->refresh = 1;

		if(S_ISLNK(node->stat->st_mode)) {
			if(ext2_read_symlink(ext2_fs, &inode, (char**)&node->symlink) == -1) {
				return -1;
			}
		}

		file = file->next;
	}

	return 0;
}

static int ext2_write_dirent(struct ext2_fs *ext2_fs, struct ext2_inode *dir, int dir_inode, const char *name, int inode, int type) {
	void *buffer = alloc(ext2_inode_read_size(dir) + ext2_fs->block_size);

	if(ext2_inode_read(ext2_fs, dir, buffer, ext2_inode_read_size(dir), 0) == -1) {
		return -1;	
	}

	for(size_t headway = 0; headway < ext2_inode_read_size(dir);) {
		struct ext2_dirent *dirent = buffer + headway;

		int expected_size = ALIGN_UP(sizeof(struct ext2_dirent) + dirent->name_length, 4);

		dirent->entry_size = expected_size;
		headway += expected_size;	

		if(expected_size == dirent->entry_size && dirent->name_length != 0) {
			continue;
		}

		dirent->entry_size = expected_size;
		dirent = buffer + headway + expected_size;

		dirent->inode_index = inode;
		dirent->entry_size = ext2_inode_read_size(dir) - headway;
		dirent->name_length = strlen(name);
		dirent->dir_type = type;

		memcpy((void*)dirent + sizeof(struct ext2_dirent), name, dirent->name_length);

		if(ext2_inode_write(ext2_fs, dir, dir_inode, buffer, ext2_inode_read_size(dir), 0) == -1) {
			return -1;
		}

		return 0;
	}

	struct ext2_dirent *dirent = buffer + ext2_inode_read_size(dir);
	uint64_t inode_size = ext2_inode_read_size(dir) + ext2_fs->block_size;

	dirent->inode_index = inode;
	dirent->entry_size = inode_size - ext2_inode_read_size(dir);
	dirent->name_length = strlen(name);
	dirent->dir_type = type;

	memcpy((void*)dirent + sizeof(struct ext2_dirent), name, dirent->name_length);

	if(ext2_inode_write(ext2_fs, dir, dir_inode, buffer, ext2_inode_read_size(dir) + sizeof(struct ext2_dirent) + strlen(name), 0) == -1) {
		return -1;
	}

	return 0;
}

static int ext2_read_symlink(struct ext2_fs *ext2_fs, struct ext2_inode *inode, char **path) {
	*path = alloc(MAX_PATH_LENGTH);

	if(ext2_inode_read_size(inode) < 60) {
		memcpy(*path, inode->blocks, 60);
	} else if(ext2_inode_read(ext2_fs, inode, *path, ext2_inode_read_size(inode), 0) == -1) {
		return -1;	
	}

	return 0;
}

static int ext2_read_dirents(struct ext2_fs *ext2_fs, struct ext2_inode *inode, struct ext2_file **files) {
	void *buffer = alloc(ext2_inode_read_size(inode));

	if(ext2_inode_read(ext2_fs, inode, buffer, ext2_inode_read_size(inode), 0) == -1) {
		return -1;	
	}

	for(size_t headway = 0; headway < ext2_inode_read_size(inode);) {
		struct ext2_dirent *dirent = buffer + headway;
		struct ext2_file *file = alloc(sizeof(struct ext2_file));

		char *name = alloc(dirent->name_length + 1);
		memcpy(name, (void*)dirent + sizeof(struct ext2_dirent), dirent->name_length);

		file->dirent = dirent;
		file->name = name;
		file->next = file;

		file->next = *files;
		*files = file;

		int expected_size = ALIGN_UP(sizeof(struct ext2_dirent) + dirent->name_length, 4);
		if(dirent->entry_size != expected_size || dirent->name_length == 0) {
			break;
		}

		headway += dirent->entry_size;
	}

	return 0; 
}

static int ext2_inode_write(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index, const void *buffer, size_t cnt, off_t offset) {
	uint64_t inode_size = ext2_inode_read_size(inode);

	for(uint64_t headway = 0; headway < cnt;) {
		uint32_t iblock = (offset + headway) / ext2_fs->block_size;
		uint32_t block;

		size_t length = cnt - headway;
		size_t block_offset = (offset + headway) % ext2_fs->block_size;

		if(length > (ext2_fs->block_size - offset)) {
			length = ext2_fs->block_size - offset;
		}
		
		int ret = ext2_inode_get_block(ext2_fs, inode, iblock, &block);
		if(ret == -1) {
			return -1;
		} else if(ret == -2) {
			block = ext2_allocate_block(ext2_fs);
			if(block == -1) {
				return -1;
			}

			if(ext2_inode_set_block(ext2_fs, inode, index, iblock, block) == -1) {
				return -1;
			}

			inode_size += length;
		}

		if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, buffer + headway, length,
					block * ext2_fs->block_size + block_offset) == -1) { 
			print("ext2: write error\n");
			return -1;
		}

		headway += length;
	}

	if(ext2_inode_write_size(ext2_fs, inode, index, inode_size) == -1) { 
		return -1;
	}

	return cnt;
}

static int ext2_inode_read(struct ext2_fs *ext2_fs, struct ext2_inode *inode, void *buffer, size_t cnt, off_t offset) {
	if(offset > ext2_inode_read_size(inode)) {
		return 0;
	}

	if((offset + cnt) > ext2_inode_read_size(inode)) {
		cnt = ext2_inode_read_size(inode) - offset;
	}

	for(uint64_t headway = 0; headway < cnt;) {
		uint32_t iblock = (offset + headway) / ext2_fs->block_size;
		uint32_t block;

		int ret = ext2_inode_get_block(ext2_fs, inode, iblock, &block);
		if(ret == -1) {
			return -1;
		}

		size_t length = cnt - headway;
		size_t block_offset = (offset + headway) % ext2_fs->block_size;

		if(length > (ext2_fs->block_size - offset)) {
			length = ext2_fs->block_size - offset;
		}

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, buffer + headway, length,
					block * ext2_fs->block_size + block_offset) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		headway += length;
	}

	return cnt;
}

static int ext2_inode_set_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index, uint32_t iblock, uint32_t block) {
	uint32_t blocks_per_level = ext2_fs->block_size / 4;

	if(iblock < 12) {
		inode->blocks[iblock] = block;
		return 0;
	}

	iblock -= 12;

	if(iblock >= blocks_per_level) { // double indirect
		iblock -= blocks_per_level;

		uint32_t indirect_block_index = iblock / blocks_per_level;
		uint32_t indirect_block_offset = iblock / blocks_per_level;
		uint32_t indirect_block = 0;

		if(indirect_block_index >= blocks_per_level) { // triply indirect
			iblock -= blocks_per_level * blocks_per_level;

			uint32_t double_indirect_block_index = iblock / blocks_per_level;
			uint32_t double_indirect_block_offset = iblock % blocks_per_level;
			uint32_t double_indirect_block = 0;

			if(!inode->blocks[14]) {
				if((inode->blocks[14] = ext2_allocate_block(ext2_fs)) == -1) {
					return -1;
				}	

				if(ext2_write_inode_entry(ext2_fs, inode, index) == -1) {
					return -1;
				}
			}

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &double_indirect_block, sizeof(double_indirect_block),
						inode->blocks[14] * ext2_fs->block_size + double_indirect_block_index * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			if(!double_indirect_block) {
				if((double_indirect_block = ext2_allocate_block(ext2_fs)) == -1) {
					return -1;
				}

				if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &double_indirect_block, sizeof(double_indirect_block),
							inode->blocks[14] * ext2_fs->block_size + double_indirect_block_index * 4) == -1) { 
					print("ext2: write error\n");
					return -1;
				}
			}

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
						double_indirect_block_index * ext2_fs->block_size + double_indirect_block * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			if(!indirect_block) {
				if((indirect_block = ext2_allocate_block(ext2_fs)) == -1) {
					return -1;
				}

				if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
							double_indirect_block_index * ext2_fs->block_size + double_indirect_block * 4) == -1) { 
					print("ext2: read error\n");
					return -1;
				}
			}

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &block, sizeof(block),
						indirect_block * ext2_fs->block_size + double_indirect_block_offset * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			return 0;
		}

		if(!inode->blocks[13]) {
			if((inode->blocks[13] = ext2_allocate_block(ext2_fs)) == -1) {
				return -1;
			}

			if(ext2_write_inode_entry(ext2_fs, inode, index) == -1) {
				return -1;
			}
		}

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
					inode->blocks[13] * ext2_fs->block_size + indirect_block_index * 4) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		if(!indirect_block) {
			if((indirect_block = ext2_allocate_block(ext2_fs)) == -1) {
				return -1;
			}

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
						inode->blocks[13] * ext2_fs->block_size + indirect_block_index * 4) == -1) { 
				print("ext2: write error\n");
				return -1;
			}
		}

		if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &block, sizeof(block),
					indirect_block * ext2_fs->block_size + indirect_block_offset * 4) == -1) { 
			print("ext2: write error\n");
			return -1;
		}

		return 0;
	}

	if(!inode->blocks[12]){
		if((inode->blocks[12] = ext2_allocate_block(ext2_fs)) == -1) {
			return -1;
		}

		if(ext2_write_inode_entry(ext2_fs, inode, index) == -1) {
			return -1;
		}

		if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, &block, sizeof(block),
					inode->blocks[12] * ext2_fs->block_size + iblock * 4) == -1) { 
			print("ext2: write error\n");
			return -1;
		}
	}
	
	return 0;
}

static int ext2_inode_get_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, uint32_t iblock, uint32_t *ret) {
	uint32_t blocks_per_level = ext2_fs->block_size / 4;
	uint32_t block = 0;

	if(iblock < 12) {
		*ret = inode->blocks[iblock];
		return 0;
	}

	iblock -= 12;

	if(iblock >= blocks_per_level) { // doubly indirect
		iblock -= blocks_per_level;

		uint32_t indirect_block_index = iblock / blocks_per_level;
		uint32_t indirect_block_offset = iblock / blocks_per_level;
		uint32_t indirect_block = 0;

		if(indirect_block_index >= blocks_per_level) { // triply indirect
			iblock -= blocks_per_level * blocks_per_level;

			uint32_t double_indirect_block_index = iblock / blocks_per_level;
			uint32_t double_indirect_block_offset = iblock % blocks_per_level;
			uint32_t double_indirect_block = 0;

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &double_indirect_block, sizeof(double_indirect_block),
						inode->blocks[14] * ext2_fs->block_size + double_indirect_block_index * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			if(!double_indirect_block) return -2;

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
						double_indirect_block_index * ext2_fs->block_size + double_indirect_block * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			if(!indirect_block) return -2;

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block),
						indirect_block * ext2_fs->block_size + double_indirect_block_offset * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			*ret = block;
			return (!block) ? -2 : 0;
		}

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
					inode->blocks[13] * ext2_fs->block_size + indirect_block_index * 4) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		if(!indirect_block) return -2;

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block),
					indirect_block * ext2_fs->block_size + indirect_block_offset * 4) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		*ret = block;
		return (!block) ? -2 : 0;
	}

	// singly indirect
	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block), inode->blocks[12] * ext2_fs->block_size + iblock * 4) == -1) { 
		print("ext2: read error\n");
		return -1;
	}

	*ret = block;
	return (!block) ? -2 : 0;
}

static int ext2_free_block(struct ext2_fs *ext2_fs, uint32_t block) {
	uint32_t bgd_index = block / ext2_fs->superblock->blocks_per_group;
	uint32_t bitmap_index = block - bgd_index * ext2_fs->superblock->blocks_per_group;

	struct ext2_bgd bgd;
	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	uint8_t *bitmap = alloc(ext2_fs->block_size);

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd.block_addr_bitmap * ext2_fs->block_size) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	if(!BIT_TEST(bitmap, bitmap_index)) {
		free(bitmap);
		return 0;
	}

	BIT_CLEAR(bitmap, bitmap_index);

	if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd.block_addr_bitmap * ext2_fs->block_size) == -1) {
		print("ext2: write error\n");
		return -1;
	}

	bgd.unallocated_inodes--;
	if(ext2_write_bgd(ext2_fs, &bgd, bgd_index) == -1){
		return -1;
	}

	free(bitmap);

	return 0;
}

static int ext2_free_inode(struct ext2_fs *ext2_fs, uint32_t inode) {
	uint32_t bgd_index = inode / ext2_fs->superblock->inodes_per_group;
	uint32_t bitmap_index = inode - bgd_index * ext2_fs->superblock->inodes_per_group;

	struct ext2_bgd bgd;
	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	uint8_t *bitmap = alloc(ext2_fs->block_size);

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd.block_addr_inode * ext2_fs->block_size) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	if(!BIT_TEST(bitmap, bitmap_index)) {
		free(bitmap);
		return 0;
	}

	BIT_CLEAR(bitmap, bitmap_index);

	if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd.block_addr_inode * ext2_fs->block_size) == -1) {
		print("ext2: write error\n");
		return -1;
	}

	bgd.unallocated_inodes--;
	if(ext2_write_bgd(ext2_fs, &bgd, bgd_index) == -1){
		return -1;
	}

	free(bitmap);

	return 0;
}

static int ext2_allocate_block(struct ext2_fs *ext2_fs) {
	struct ext2_bgd bgd;

	for(size_t i = 0; i < ext2_fs->bgd_cnt; i++) {
		if(ext2_read_bgd(ext2_fs, &bgd, i) == -1) {
			return -1;
		}

		int block_index = ext2_bgd_allocate_inode(ext2_fs, &bgd, i);
		if(block_index == -1) {
			continue;
		}

		return block_index + i * ext2_fs->superblock->blocks_per_group;
	}

	return -1;
}

static int ext2_allocate_inode(struct ext2_fs *ext2_fs) {
	struct ext2_bgd bgd;

	for(size_t i = 0; i < ext2_fs->bgd_cnt; i++) {
		if(ext2_read_bgd(ext2_fs, &bgd, i) == -1) {
			return -1;
		}

		int inode_index = ext2_bgd_allocate_inode(ext2_fs, &bgd, i);
		if(inode_index == -1) {
			continue;
		}

		return inode_index + i * ext2_fs->superblock->inodes_per_group;
	}

	return -1;
}

static int ext2_bgd_allocate_inode(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index) {
	if(bgd->unallocated_inodes == 0) {
		return -1;
	}

	uint8_t *bitmap = alloc(ext2_fs->block_size);

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_inode * ext2_fs->block_size) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	for(size_t i = 0; i < ext2_fs->block_size; i++) {
		if(!BIT_TEST(bitmap, i)) {
			BIT_SET(bitmap, i);

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_inode * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			bgd->unallocated_inodes--;
			if(ext2_write_bgd(ext2_fs, bgd, bgd_index) == -1){
				return -1;
			}

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size,
						bgd->block_addr_inode * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			free(bitmap);

			return i;
		}
	}

	free(bitmap);

	return -1;
}

static int ext2_bgd_allocate_block(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index) {
	if(bgd->unallocated_blocks == 0) {
		return -1;
	}

	uint8_t *bitmap = alloc(ext2_fs->block_size);

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_bitmap * ext2_fs->block_size) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	for(size_t i = 0; i < ext2_fs->block_size; i++) {
		if(!BIT_TEST(bitmap, i)) {
			BIT_SET(bitmap, i);

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_bitmap * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			bgd->unallocated_blocks--;
			if(ext2_write_bgd(ext2_fs, bgd, bgd_index) == -1){
				return -1;
			}

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size,
						bgd->block_addr_bitmap * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			free(bitmap);

			return i;
		}
	}

	free(bitmap);

	return -1;
}

static int ext2_read_inode_entry(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index) {
	int table_index = (index - 1) % ext2_fs->superblock->inodes_per_group;
	int bgd_index = (index - 1) / ext2_fs->superblock->inodes_per_group;

	struct ext2_bgd bgd;

	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, inode, sizeof(struct ext2_inode), bgd.inode_table_block * ext2_fs->block_size + ext2_fs->superblock->inode_size * table_index) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	return 0;
}

static int ext2_write_inode_entry(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index) {
	int table_index = (index - 1) % ext2_fs->superblock->inodes_per_group;
	int bgd_index = (index - 1) / ext2_fs->superblock->inodes_per_group;

	struct ext2_bgd bgd;

	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, inode, sizeof(struct ext2_inode), bgd.inode_table_block * ext2_fs->block_size + ext2_fs->superblock->inode_size * table_index) == -1) {
		print("ext2: writ error\n");
		return -1;
	}

	return 0;
}

static int ext2_read_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index) {
	uint64_t bgd_offset = (ext2_fs->block_size >= 2048) ? ext2_fs->block_size : ext2_fs->block_size * 2;
	
	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, bgd, sizeof(struct ext2_bgd), bgd_offset + index * sizeof(struct ext2_bgd)) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	return 0;
}

static int ext2_write_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index) {
	uint64_t bgd_offset = (ext2_fs->block_size >= 2048) ? ext2_fs->block_size : ext2_fs->block_size * 2;
	
	if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bgd, sizeof(struct ext2_bgd), bgd_offset + index * sizeof(struct ext2_bgd)) == -1) {
		print("ext2: write error\n");
		return -1;
	}

	return 0;
}

int ext2_init(struct partition *partition) {
	struct ext2_superblock *superblock = alloc(sizeof(struct ext2_superblock));

	if(partition->cdev->bops->read(partition->cdev, superblock, sizeof(struct ext2_superblock), 1024) == -1) {
		print("ext2: partition: read error\n");
	}

	if(superblock->signature != EXT2_SIGNATURE) {
		return -1;
	}

	struct ext2_fs *ext2_fs = alloc(sizeof(struct ext2_fs));

	ext2_fs->partition = partition;
	ext2_fs->blkdev = partition->blkdev;

	ext2_fs->block_size = 1024 << superblock->block_size;
	ext2_fs->frag_size = 1024 << superblock->frag_size;
	ext2_fs->bgd_cnt = DIV_ROUNDUP(superblock->block_cnt, superblock->blocks_per_group);

	print("ext2: filesystem detected on %s\n", partition->partition_path);
	print("ext2: inode count: %x\n", superblock->inode_cnt);
	print("ext2: inodes per group: %x\n", superblock->inodes_per_group);
	print("ext2: block count: %x\n", superblock->block_cnt);
	print("ext2: blocks per group: %x\n", superblock->blocks_per_group);
	print("ext2: block size: %x\n", ext2_fs->block_size);
	print("ext2: bgd count: %x\n", ext2_fs->bgd_cnt);

	ext2_fs->superblock = superblock;
	ext2_fs->root_inode = alloc(sizeof(struct ext2_inode));	

	struct filesystem *filesystem = alloc(sizeof(struct filesystem));
	*filesystem = (struct filesystem) {
		.create = ext2_create,
		.truncate = ext2_truncate,
		.refresh = ext2_refresh,
		.private_data = ext2_fs
	};

	ext2_fs->filesystem = filesystem;

	if(ext2_read_inode_entry(ext2_fs, ext2_fs->root_inode, 2) == -1) {
		print("error reading root inode\n");
		return -1;
	}

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);
	stat->st_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	stat->st_ino = 2;
	if(vfs_mount(vfs_root, stat, filesystem, &ext2_fops) == -1) {
		print("mount failed\n");
	}

	return 0;
}
