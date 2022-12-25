#pragma once

#include <fs/fd.h>

#define GPT_SIGNATURE 0x5452415020494645
#define MBR_SIGNATURE 0xaa55

#define SECTOR_SIZE 0x200

struct partition;

struct blkdev {
	struct file_handle *disk;

	struct cdev *cdev;

	const char *device_name;
	const char *device_prefix;

	const char *serial_number;
	const char *firmware_revision;
	const char *model_number;

	int partition_major;
	int partition_minor;
	struct partition *partitions;
};

struct partition {
	struct blkdev *blkdev;
	struct file_handle *handle;

	char uuid[16];
	const char *partition_path;

	uint64_t lba_start;
	uint64_t lba_cnt;

	struct partition *next;
};

struct mbr_partition {
	uint8_t drive_status;
	uint8_t chs_start[3];
	uint8_t type;
	uint8_t chs_end[3];
	uint32_t lba_start;
	uint32_t lba_cnt;
} __attribute__((packed));

struct gpt_partition {
	uint64_t partition_type_guid[2]; 
	uint64_t partition_guid[2];
	uint64_t starting_lba;
	uint64_t last_lba;
	uint64_t flags;
	uint64_t name[9];
};

struct gpt_partition_table {
	uint64_t identifier;
	uint32_t version;
	uint32_t hdr_size;
	uint32_t checksum;
	uint32_t reserved0;
	uint64_t hdr_lba;
	uint64_t alt_hdr_lba;
	uint64_t first_block;
	uint64_t last_block;
	uint64_t guid[2];
	uint64_t partition_array_lba;
	uint32_t partition_entry_cnt;
	uint32_t partition_entry_size;
	uint32_t crc32_partition_array;
};

int register_blkdev(struct blkdev *blkdev);
