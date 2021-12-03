#include <sys/syscall.h>
#include <unistd.h>

int create() {
	syscall(SYS_memfd_create, "test", 0);
}
