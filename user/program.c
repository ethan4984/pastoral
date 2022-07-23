#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

static void s(int sss) {
	(void) sss;
	printf("here\n");
	exit(0);
}


int main() {
	setbuf(stdin, NULL);
	signal(SIGINT, s);
	raise(SIGINT);
	for (;;) {}
}
