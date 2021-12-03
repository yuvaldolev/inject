#include <stdio.h>

void __attribute__((constructor)) init(void) {
	printf("Agent is running in remote process!\n");
}
