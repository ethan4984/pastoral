#pragma once

#include <lib/types.h>

// terminal ioctls

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5303
#define TCSETSF 0x5304

#define TIOCGPGRP 0x540f
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define TIOCSCTTY 0x540e
#define TIOCGSID 0x5429

#define TIOCGPTN 0x80045430
#define TIOCSPTLCK 0x40045431

struct winsize {
	uint16_t ws_row;
	uint16_t ws_col;
	uint16_t ws_xpixel;
	uint16_t ws_ypixel;
};
