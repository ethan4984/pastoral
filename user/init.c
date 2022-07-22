#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static void hand(int s) {
	printf("here\n");
	for (;;) {}
}

int main() {
	printf("hello world program\n");
	signal(SIGINT, hand);
	kill(getpid(), SIGINT);
	for(;;);
}
