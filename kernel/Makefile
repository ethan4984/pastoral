KERNEL := pastoral.elf

CC ?= cc
LD ?= ld

CFLAGS  ?= -Wall -Wextra -O0 -pipe -fsanitize=undefined
LDFLAGS ?=

INTERNALLDFLAGS :=		 \
	-Tlinker.ld			\
	-nostdlib			  \
	-zmax-page-size=0x1000 \
	-static				\
	-pie				   \
	--no-dynamic-linker	\
	-ztext

INTERNALCFLAGS :=		\
	-I.				  \
	-Ilib				 \
	-std=gnu11		   \
	-ffreestanding	   \
	-fno-stack-protector \
	-fpie				\
	-mno-80387		   \
	-mno-mmx			 \
	-mno-3dnow		   \
	-mno-sse			 \
	-mno-sse2			\
	-mno-red-zone		\
	-MMD				 \
	-Wno-sign-compare

CFILES	  := $(shell find ./ -type f -name '*.c')
ASMFILES	:= $(shell find ./ -type f -name '*.asm')
REALFILES 	:= $(shell find ./ -type f -name '*.real')
OBJ		 := $(CFILES:.c=.o) $(ASMFILES:.asm=.o)
BINS		:= $(REALFILES:.real=.bin)
HEADER_DEPS := $(CFILES:.c=.d)

.PHONY: all
all: $(KERNEL)

$(KERNEL): $(BINS) $(OBJ)
	$(LD) $(OBJ) $(LDFLAGS) $(INTERNALLDFLAGS) -o $@

-include $(HEADER_DEPS)

%.o: %.c
	$(CC) $(CFLAGS) $(INTERNALCFLAGS) -c $< -o $@

%.o: %.asm
	nasm -felf64 $< -o $@

%.bin: %.real
	nasm -fbin $< -o $@

.PHONY: clean
clean:
	rm -rf $(KERNEL) $(OBJ) $(HEADER_DEPS) $(BINS)
