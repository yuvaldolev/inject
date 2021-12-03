#define _GNU_SOURCE
#include <inttypes.h>
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

extern unsigned char libagent_so[];
extern unsigned int libagent_so_len;

static void remote_write_memory(
		pid_t pid,
		void *src,
		void *dst,
		size_t size) {
	struct iovec local_iovec = {
		.iov_base = src,
		.iov_len = size
	};

	struct iovec remote_iovec = {
		.iov_base = dst,
		.iov_len = size
	};

	process_vm_writev(pid, &local_iovec, 1, &remote_iovec, 1, 0);
}

static void remote_dlopen(
		pid_t pid,
		uintptr_t dlopen_addr,
		void *code,
		const char *so_path) {
	uint8_t *code_cursor = code;	

	// Backup the registers.
	struct user_regs_struct backup_registers;
	ptrace(PTRACE_GETREGS, pid, NULL, &backup_registers);

	// Backup the current code under rip.
	long backup_code = ptrace(
			PTRACE_PEEKTEXT,
			pid,
			(void*)backup_registers.rip,
			NULL
	);

	// Write the so path to the remote process.
	remote_write_memory(
			pid,
			(void*)so_path,
			(void*)(code_cursor + 100),
			strlen(so_path) + 1
	);

	// Set the registers to perform the `dlopen` call.
	struct user_regs_struct registers = backup_registers;
	registers.rax = dlopen_addr;
	registers.rdi = (unsigned long long)(code_cursor + 100); // filename
	registers.rsi = RTLD_LAZY; // flags

	ptrace(PTRACE_SETREGS, pid, NULL, &registers);

	// Set the code under rip to perform the `dlopen` call.
	ptrace(PTRACE_POKETEXT, pid, (void*)backup_registers.rip, 0xCCD0FF);

	// Perform the `dlopen` call.
	ptrace(PTRACE_CONT, pid, NULL, NULL);	
	int status;
	waitpid(pid, &status, WUNTRACED);

	// Restore the remote process's state.
	ptrace(PTRACE_POKETEXT, pid, (void*)backup_registers.rip, backup_code);
	ptrace(PTRACE_SETREGS, pid, NULL, &backup_registers);
}

static unsigned long long remote_syscall(
		pid_t pid,
		unsigned long long number,
		unsigned long long arg0,
		unsigned long long arg1,
		unsigned long long arg2,
		unsigned long long arg3,
		unsigned long long arg4,
		unsigned long long arg5) {
	// Backup the registers.
	struct user_regs_struct backup_registers;
	ptrace(PTRACE_GETREGS, pid, NULL, &backup_registers);

	// Backup the current code under rip.
	long backup_code = ptrace(
			PTRACE_PEEKTEXT,
			pid,
			(void*)backup_registers.rip,
			NULL
	);


	// Set the registers to perform the syscall.
	struct user_regs_struct registers = backup_registers;
	registers.rax = number;
	registers.rdi = arg0;
	registers.rsi = arg1;
	registers.rdx = arg2;
	registers.r10 = arg3;
	registers.r8 = arg4;
	registers.r9 = arg5;

	ptrace(PTRACE_SETREGS, pid, NULL, &registers);

	// Set the code under rip to perform the `syscall` instruction.
	ptrace(PTRACE_POKETEXT, pid, (void*)backup_registers.rip, 0x050F);

	// Perform the syscall.
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	int status;
	waitpid(pid, &status, WUNTRACED);

	// Retrieve syscall's result.
	ptrace(PTRACE_GETREGS, pid, NULL, &registers);

	// Restore the remote process's state.
	ptrace(PTRACE_POKETEXT, pid, (void*)backup_registers.rip, backup_code);
	ptrace(PTRACE_SETREGS, pid, NULL, &backup_registers);
	
	// Retrieve the mmap result address.
	return registers.rax;
}

static void* remote_mmap(pid_t pid, size_t size) {
	return (void*)remote_syscall(
			pid,
			SYS_mmap,
			0,
			size,
			PROT_READ | PROT_WRITE | PROT_EXEC,
			MAP_PRIVATE | MAP_ANONYMOUS,
			-1,
			0
	);
}

static int remote_memfd_create(pid_t pid, const char *name) {
	size_t name_size = strlen(name) + 1;
	void *remote_name = remote_mmap(pid, 4096);
	remote_write_memory(pid, (void*)name, remote_name, name_size);
	return (int)remote_syscall(
			pid,
			SYS_memfd_create,
			(unsigned long long)remote_name,
			0,
			0,
			0,
			0,
			0
	);
}
static void* load_symbol(const char *so, const char *symbol) {
	void *address = NULL;

	// Open the so.
	void *so_handle = dlopen(so, RTLD_LAZY);
	if (NULL == so_handle) {
		goto out;
	}

	// Retrieve the symbol from the loaded so.
	address = dlsym(so_handle, symbol);

	// Close the so.
	dlclose(so_handle);

out:
	return address;
}

static uintptr_t remote_find_symbol(pid_t pid, const char *symbol) {
	uintptr_t symbol_address = 0;

	// Format the remote maps file path.
	char maps_path[PATH_MAX];
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	// Open the remote maps file.
	FILE *maps = fopen(maps_path, "r");
	if (NULL == maps) {
		goto out;
	}

	// Search for the remote symbol in the maps file and retrieve its address.
	char line[9076];
	while (NULL != fgets(line, sizeof(line), maps)) {
		if (NULL != strstr(line, symbol)) {
			symbol_address = strtoull(line, NULL, 16);
			break;
		}
	}

	// Close the maps files.
	fclose(maps);

out:
	return symbol_address;
}

int main(int argc, const char* const argv[]) {
	int ret = 0;

	if (2 != argc) {
		fprintf(stderr, "USAGE: %s <target-pid>\n", argv[0]);
		ret = 1;
		goto out;
	}

	long int target_pid_long = (pid_t)strtol(argv[1], NULL, 10);
	if ((LONG_MIN == target_pid_long) || (LONG_MAX == target_pid_long)) {
		fprintf(stderr, "Invalid target pid [%s], error(%d): [%s]", argv[1], errno, strerror(errno));
		ret = 1;
		goto out;
	}
	pid_t target_pid = (pid_t)target_pid_long;
	printf("Injecting agent into target process: [%d]\n", target_pid);

	// Retrieve the address of libc
	pid_t pid = getpid();
	uint64_t local_libc = remote_find_symbol(pid, "libc-");

	// Retrieve the address of `__libc_dlopen_mode`.
	void *local_dlopen = load_symbol("libc.so.6", "__libc_dlopen_mode");
	if (NULL == local_dlopen) {
		fprintf(stderr, "Failed retrieving __libc_dlopen_mode() from libc, error: [%s]\n", dlerror());
		ret = 1;
		goto out;
	}
	printf("_libc_dlopen_mode() found at address: [%p]\n", local_dlopen);

	// Find the address of libc in the target process.
	uintptr_t remote_libc = remote_find_symbol(target_pid, "libc-");
	printf("Located libc.so in target PID [%d] at address: [%p]\n", target_pid, (void*)remote_libc);

	// Due to ASLR, we need to calculate the address in the target process
	uintptr_t dlopen_offset = (uintptr_t)local_dlopen - local_libc;
	printf("_libc_dlopen_mode() offset to libc found to be [%lu] bytes\n", dlopen_offset);
	uintptr_t remote_dlopen_addr = remote_libc + dlopen_offset;
	printf("_libc_dlopen_mode() in target process is at address [%p]\n", (void*)remote_dlopen_addr);

	// Attach to the target process.
	ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
	
	// Wait for the attachment to complete.
	int status;
	waitpid(target_pid, &status, WUNTRACED);

	// Map remote pages to store our code.
	printf("Mapping remote pages to store agent so\n");
	void *remote_code = remote_mmap(target_pid, 16192);
	printf("Mapped remote code address: [%p]\n", remote_code);

	// Run dlopen remotely.
 	// printf("Running _libc_dlopen_mode() remotely\n");
 	// remote_dlopen(
 	// 		target_pid,
 	// 		remote_dlopen_addr,
 	// 		remote_code,
 	// 		"/app/libagent.so"
 	// );
 	// printf("Successfully ran _libc_dlopen_mode() remotely\n");

	// Create a memfd in the remote process.
	printf("Creating a remote memory fd\n");
	int remote_memfd = remote_memfd_create(target_pid, "agent");
	printf("Created remote memory fd: [%d]\n", remote_memfd);

out:
	// Detach from the target process.
 	ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

	return ret;
}
