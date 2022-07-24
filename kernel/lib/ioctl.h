#pragma once

#include <lib/types.h>

// terminal ioctls

#define TIOCGPGRP 0x540f
#define TIOCSPGRP 0x5410
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define TIOCGSID 0x5429


struct winsize {
	uint16_t ws_row;
	uint16_t ws_col;
	uint16_t ws_xpixel;
	uint16_t ws_ypixel;
};


