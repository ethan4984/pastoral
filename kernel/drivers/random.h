#pragma once

#define URANDOM_MAJOR 1
#define URANDOM_MINOR 9

#define RNDGETENTCNT
#define RNDADDTOENTCNT
#define RNDADDENTROPY
#define RNDZAPENTCNT
#define RNDCLEARPOOL

void random_init();
