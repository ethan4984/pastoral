#include <fs/ext2/ext2.h>
#include <debug.h>

static int ext2_read_inode(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index);
static int ext2_write_inode(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index);
static int ext2_read_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index);
static int ext2_write_bgd(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int index);
static int ext2_bgd_allocate_inode(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index);
static int ext2_bgd_allocate_block(struct ext2_fs *ext2_fs, struct ext2_bgd *bgd, int bgd_index);
static int ext2_allocate_inode(struct ext2_fs *ext2_fs);
static int ext2_allocate_block(struct ext2_fs *ext2_fs);
static int ext2_free_inode(struct ext2_fs *ext2_fs, uint32_t inode);
static int ext2_free_block(struct ext2_fs *ext2_fs, uint32_t block);
static int ext2_inode_set_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, uint32_t block);
static uint32_t ext2_inode_get_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, uint32_t block);

static uint32_t ext2_inode_get_block(struct ext2_fs *ext2_fs, struct ext2_inode *inode, uint32_t iblock) {
	uint32_t blocks_per_level = ext2_fs->block_size / 4;
	uint32_t block = 0;

	if(iblock < 12) {
		return inode->blocks[iblock];
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

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
						double_indirect_block_index * ext2_fs->block_size + double_indirect_block * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block),
						indirect_block * ext2_fs->block_size + double_indirect_block_offset * 4) == -1) { 
				print("ext2: read error\n");
				return -1;
			}

			return block;
		}

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &indirect_block, sizeof(indirect_block),
					inode->blocks[13] * ext2_fs->block_size + indirect_block_index * 4) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block),
					indirect_block * ext2_fs->block_size + indirect_block_offset * 4) == -1) { 
			print("ext2: read error\n");
			return -1;
		}

		return block;
	}

	// singly indirect
	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, &block, sizeof(block), inode->blocks[12] * ext2_fs->block_size + iblock * 4) == -1) { 
		print("ext2: read error\n");
		return -1;
	}

	return block;
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
			BIT_TEST(bitmap, i);

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_inode * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			bgd->unallocated_inodes--;
			if(ext2_write_bgd(ext2_fs, bgd, bgd_index) == -1){
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
			BIT_TEST(bitmap, i);

			if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, bitmap, ext2_fs->block_size, bgd->block_addr_bitmap * ext2_fs->block_size) == -1) {
				print("ext2: write error\n");
				return -1;
			}

			bgd->unallocated_blocks--;
			if(ext2_write_bgd(ext2_fs, bgd, bgd_index) == -1){
				return -1;
			}

			free(bitmap);

			return i;
		}
	}

	free(bitmap);

	return -1;
}

static int ext2_read_inode(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index) {
	int table_index = (index - 1) % ext2_fs->superblock->inodes_per_group;
	int bgd_index = (index - 1) / ext2_fs->superblock->inodes_per_group;

	struct ext2_bgd bgd;

	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	if(ext2_fs->partition->cdev->bops->read(ext2_fs->partition->cdev, inode, sizeof(struct ext2_inode), table_index * ext2_fs->block_size + ext2_fs->superblock->inode_size * table_index) == -1) {
		print("ext2: read error\n");
		return -1;
	}

	return 0;
}

static int ext2_write_inode(struct ext2_fs *ext2_fs, struct ext2_inode *inode, int index) {
	int table_index = (index - 1) % ext2_fs->superblock->inodes_per_group;
	int bgd_index = (index - 1) / ext2_fs->superblock->inodes_per_group;

	struct ext2_bgd bgd;

	if(ext2_read_bgd(ext2_fs, &bgd, bgd_index) == -1) {
		return -1;
	}

	if(ext2_fs->partition->cdev->bops->write(ext2_fs->partition->cdev, inode, sizeof(struct ext2_inode), table_index * ext2_fs->block_size + ext2_fs->superblock->inode_size * table_index) == -1) {
		print("ext2: writeerror\n");
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

	if(ext2_read_inode(ext2_fs, ext2_fs->root_inode, 2) == -1) {
		return -1;
	}
	
	return 0;
}
