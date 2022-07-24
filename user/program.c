#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static void sighand(int sig) {
	printf("sigint %d\n", sig);
	exit(EXIT_SUCCESS);
}

int main() {
	printf("Hello\n");
	signal(SIGINT, sighand);
	raise(SIGINT);
	for(;;);
}
