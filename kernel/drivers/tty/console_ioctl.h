#pragma once

#include <lib/types.h>

#define KDSETMODE 0x4b3a
#define KDGETMODE 0x4b3b
#define KD_TEXT 0
#define KD_GRAPHICS 1

#define VT_GETMODE 0x5601
#define VT_SETMODE 0x5602

#define VT_AUTO 0
#define VT_PROCESS 1
#define VT_ACKACQ 2

struct vt_mode {
	char mode;
	char waitv;
	short relsig;
	short acqsig;
	short frsig;
};
