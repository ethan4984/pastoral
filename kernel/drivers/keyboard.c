#include <drivers/keyboard.h>
#include <drivers/tty/tty.h>
#include <int/apic.h>
#include <int/idt.h>
#include <debug.h>

static void ps2_enable();
static void ps2_disable();
static void ps2_flush_buffer();

static bool shift_active;
static bool shift_lock;
static bool ctrl_active;
static bool extended_map;

static char keymap_plain[] = {
	'\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	'-', '=', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
	'o', 'p', '[', ']', '\n', '\0', 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ';', '\'', '`', '\0', '\\', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', ',', '.',  '/', '\0', '\0', '\0', ' '
};

static char keymap_caps[] = {
	'\0', '\0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
	'-','=', '\b', '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I',
	'O', 'P', '[', ']', '\n', '\0', 'A', 'S', 'D', 'F', 'G', 'H',
	'J', 'K', 'L', ';', '\'', '`', '\0', '\\', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', ',', '.', '/', '\0', '\0', '\0', ' '
};

static char keymap_shift_nocaps[] = {
	'\0', '\0', '!', '@', '#',	'$', '%', '^',	'&', '*', '(', ')',
	'_', '+', '\b', '\t', 'Q',	'W', 'E', 'R',	'T', 'Y', 'U', 'I',
	'O', 'P', '{', '}', '\n',  '\0', 'A', 'S',	'D', 'F', 'G', 'H',
	'J', 'K', 'L', ':', '\"', '~', '\0', '|', 'Z', 'X', 'C', 'V',
	'B', 'N', 'M', '<', '>',  '?', '\0', '\0', '\0', ' '
};

static char keymap_shift_caps[] = {
	'\0', '\0', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
	'_', '+', '\b', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i',
	'o', 'p', '{', '}', '\n',  '\0', 'a', 's', 'd', 'f', 'g', 'h',
	'j', 'k', 'l', ':', '\"', '~', '\0', '|', 'z', 'x', 'c', 'v',
	'b', 'n', 'm', '<', '>',  '?', '\0', '\0', '\0', ' '
};

static char function_table_raw[] = {
	'\033', '[', 'A', 0, // 4
	'\033', '[', 'B', 0, // 8
	'\033', '[', 'C', 0, // 12
	'\033', '[', 'D', 0, // 16
	'\033', '[', '3', '~', 0, // 21
	'\033', '[', '1', '~', 0, // 26
	'\033', '[', '4', '~', 0, // 31
};

static char *function_table[] = {
	function_table_raw + 0,
	function_table_raw + 4,
	function_table_raw + 8,
	function_table_raw + 12,
	function_table_raw + 21,
	function_table_raw + 26,
	function_table_raw + 31,
};

static int ps2_get_character(char *character) {
	uint8_t scancode = inb(KDB_PS2_DATA);
	bool release = scancode & 0x80;

	if(scancode == 0x2a || scancode == 0xaa
		|| scancode == 0x36 || scancode == 0xb6) {
		if(!release) {
			shift_active = true;
		} else {
			shift_active = false;
		}

		return -1;
	}

	if(scancode == 0x1d || scancode == 0x9d) {
		if(!release) {
			ctrl_active = true;
		} else {
			ctrl_active = false;
		}

		return -1;
	}

	if(scancode == 0x3a) {
		shift_lock ^= 1;
		return -1;
	}

	if(scancode == 0xe0) {
		extended_map = true;
		return -1;
	}

	if(extended_map == false) {
		goto noextend;
	}

	extended_map = false;

	switch(scancode) {
		case 0x53: // del
			return 5;
		case 0x47: // home
			return 6;
		case 0x4f: // end
			return 7;
		case 0x4b: // left
			return 3;
		case 0x48: // up
			return 0;
		case 0x50: // down
			return 1;
		case 0x4d: // right
			return 2;
		default:
			return -1;
	}
noextend:
	if(release) {
		return -1;
	}

	if(scancode < sizeof(keymap_plain)) {
		if(!shift_lock && !shift_active) {
			*character = keymap_plain[scancode];
		} else if(shift_lock && !shift_active) {
			*character = keymap_caps[scancode];
		} else if(!shift_lock && shift_active) {
			*character = keymap_shift_nocaps[scancode];
		} else if(shift_lock && shift_active) {
			*character = keymap_shift_caps[scancode];
		}
	}

	if(ctrl_active) {
		if((*character >= 'A' && (*character <= 'z'))) {
			if(*character >= 'a') {
				*character = *character - 'a' + 1;
			} else if(*character <= '^') {
				*character = *character - 'A' + 1;
			}
		}
	}

	return -1;
}

void ps2_handler(struct registers*, void*) {
	if(!active_tty) {
		ps2_flush_buffer();
		return;
	}

	spinlock_irqsave(&active_tty->input_lock);

	for(;;) {
		uint8_t status = inb(KDB_PS2_STATUS);

		if((status & (1 << 0)) == 0) {
			break;
		}

		if(status & (1 << 5)) {
			continue;
		}

		char character = '\0';
		int function = ps2_get_character(&character);
		
		if(ctrl_active) {
			tty_handle_signal(active_tty, character);
		}

		if(character != '\0') {
			circular_queue_push(&active_tty->input_queue, &character);
			continue;
		}

		if(function == -1) {
			continue;
		}

		char *sequence = function_table[function];

		for(size_t i = 0; i < strlen(sequence); i++) {
			circular_queue_push(&active_tty->input_queue, &sequence[i]);
		}
	}

	spinrelease_irqsave(&active_tty->input_lock);
}

static bool ps2_validate() {
	if(fadt) {
		if(fadt->iapc_boot_arch & (1 << 1)) {
			return true;
		}

		return false;
	}

	return true;
}

static void ps2_enable() {
	while(inb(KDB_PS2_STATUS) & (1 << 1)) asm ("pause");
	outb(KDB_PS2_COMMAND, 0xae);

	while(inb(KDB_PS2_STATUS) & (1 << 1)) asm ("pause");
	outb(KDB_PS2_COMMAND, 0xa8);
}

static void ps2_disable() {
	while(inb(KDB_PS2_STATUS) & (1 << 1)) asm ("pause");
	outb(KDB_PS2_COMMAND, 0xad);

	while(inb(KDB_PS2_STATUS) & (1 << 1)) asm ("pause");
	outb(KDB_PS2_COMMAND, 0xa7);
}

static void ps2_flush_buffer() {
	while(inb(KDB_PS2_STATUS) & (1 << 0)) {
		inb(KDB_PS2_DATA);
	}
}

void ps2_init() {
	if(!ps2_validate()) {
		print("ps2: device not present\n");
		return;
	}

	ps2_disable();
	ps2_flush_buffer();

	int ps2_vector = idt_alloc_vector(ps2_handler, NULL);
	ioapic_set_irq_redirection(xapic_read(XAPIC_ID_REG_OFF), ps2_vector, 1, false);

	ps2_enable();
}
