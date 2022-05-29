#pragma once

struct ustar_header {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
} __attribute__((packed));

#define USTAR_REGTYPE '0'
#define USTAR_AREGTYPE '\0'
#define USTAR_LNKTYPE '1'
#define USTAR_SYMTYPE '2'
#define USTAR_CHRTYPE '3'
#define USTAR_BLKTYPE '4'
#define USTAR_DIRTYPE '5'
#define USTAR_FIFOTYPE '6'
#define USTAR_CONTTYPE '7'

#define USTAR_MAGIC "ustar"
