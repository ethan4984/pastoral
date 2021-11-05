#pragma once

#include <stdint.h>
#include <stddef.h>

typedef int64_t off_t;
typedef int64_t ssize_t;

typedef ssize_t pid_t;
typedef ssize_t tid_t;
typedef ssize_t uid_t;
typedef ssize_t gid_t;

typedef uint64_t dev_t;
typedef uint64_t ino_t;
typedef int32_t mode_t;
typedef int32_t nlink_t;
typedef int64_t blksize_t;
typedef int64_t blkcnt_t;

typedef int64_t time_t; 
typedef int64_t clockid_t;

struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

#define S_IFMT 0x0f000
#define S_IFBLK 0x06000
#define S_IFCHR 0x02000
#define S_IFIFO 0x01000
#define S_IFREG 0x08000
#define S_IFDIR 0x04000
#define S_IFLNK 0x0a000
#define S_IFSOCK 0x0c000

#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR) 
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISLNK(m) (((m) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 0700
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#define S_IRXWG 070
#define S_IRGRP 040
#define S_IWGRP 020
#define S_IXGRP 010
#define S_IRWXO 07
#define S_IROTH 04
#define S_IWOTH 02
#define S_IXOTH 01
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000

#define F_DUPFD 1
#define F_DUPFD_CLOEXEC 2
#define F_GETFD 3
#define F_SETFD 4
#define F_GETFL 5
#define F_SETFL 6
#define F_GETLK 7
#define F_SETLK 8
#define F_SETLKW 9
#define F_GETOWN 10
#define F_SETOWN 11

#define O_APPEND 0x8
#define O_CREAT 0x10
#define O_DIRECTORY 0x20
#define O_EXCL 0x40
#define O_NOCTTY 0x80
#define O_NOFOLLOW 0x100
#define O_TRUNC 0x200
#define O_NONBLOCK 0x400
#define O_DSYNC 0x800
#define O_RSYNC 0x1000
#define O_SYNC 0x2000
#define O_CLOEXEC 0x4000

#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_SET 3

struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    off_t st_size;
    struct timespec st_atim;
    struct timespec st_mtim;
    struct timespec st_ctim;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
};

struct asset {
	ssize_t (*read)(struct asset*, void*, off_t, off_t, void*);
	ssize_t (*write)(struct asset*, void*, off_t, off_t, const void*);
	int (*ioctl)(struct asset*, void*, uint64_t req, void *args);
	int (*resize)(struct asset*, void*, off_t, off_t);

	struct stat *stat;
	char lock;
};
