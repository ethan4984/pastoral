#pragma once

typedef unsigned int cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;


#define _POSIX_VDISABLE (-1)


// c_iflag
#define BRKINT 0x01
#define ICRNL 0x02
#define IGNBRK 0x04
#define IGNCR 0x08
#define IGNPAR 0x10
#define INLCR 0x20
#define INPCK 0x40
#define ISTRIP 0x80
#define IXANY 0x100
#define IXOFF 0x200
#define IXON 0x400
#define PARMRK 0x800

// c_oflag
#define OPORT 0x01
#define ONLCR 0x02
#define OCRNL 0x04
#define ONLRET 0x10
#define OFDEL 0x20
#define OFILL 0x40

#define NLDLY 0x80
#define NL0 0x00
#define NL1 0x80

#define CRDLY 0x300
#define CR0 0x00
#define CR1 0x100
#define CR2 0x200
#define CR3 0x300

#define TABDLY 0xC00
#define TAB0 0x000
#define TAB1 0x400
#define TAB2 0x800
#define TAB3 0xC00

#define BSDLY 0x1000
#define BS0 0x00
#define BS1 0x1000

#define VTDLY 0x2000
#define VT0 0x00
#define VT1 0x2000

#define FFDLY 0x4000
#define FF0 0x00
#define FF1 0x4000

// c_cflag
#define CSIZE 0x03
#define CS5 0x00
#define CS6 0x01
#define CS7 0x02
#define CS8 0x03

#define CSTOPB 0x04
#define CREAD 0x08
#define PARENB 0x10
#define PARODD 0x20
#define HUPCL 0x40
#define CLOCAL 0x80

// c_lflag
#define ECHO 0x01
#define ECHOE 0x02
#define ECHOK 0x04
#define ECHONL 0x08
#define ICANON 0x10
#define IEXTEN 0x20
#define ISIG 0x40
#define NOFLSH 0x80
#define TOSTOP 0x100

// Mlibc clashes these two definitions. ECHOCTL is more
// important for us, so support that first.
//#define ECHOPRT 0x200
#define ECHOCTL 0x200

// c_ccs
#define NCCS 11
#define VEOF 0
#define VEOL 1
#define VERASE 2
#define VINTR 3
#define VKILL 4
#define VMIN 5
#define VQUIT 6
#define VSTART 7
#define VSTOP 8
#define VSUSP 9
#define VTIME 10

// termios
struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_cc[NCCS];
	speed_t ibaud;
	speed_t obaud;
};
