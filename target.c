#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
	printf("pid: [%d]\n", getpid());

	for (;;) {
		printf("Zzzzz\n");
		sleep(1);
	}

	return 1;
}
