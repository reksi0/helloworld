/* 
 * Program that turn another program into hello world app, x86 only.
 * Usage: progname pid
 * where pid is a pid of proccess to turn into hello world app.
 */


#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <termios.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define WORD_ROUND(x) (((x) + 3) / 4 * 4)

void usage() {
	printf("progname pid\n");
	exit(1);
}

int poke_data(pid_t pid, unsigned start_addr, unsigned int* data, size_t size) {
	int i;
	for (i = 0; i < WORD_ROUND(size) / 4; i++) {
		if (ptrace(PTRACE_POKETEXT, pid, start_addr + i * 4, data[i]) == -1) {
			perror("PTRACE_POKETEXT");
			return 1;
		}
	}
	return 0;
}

int main(int argc, char* argv[]) {
	unsigned term_address, hw_address, hw_len;
	char hello_world[] = "\nHello world!\n";
	struct pt_regs regs;
	struct termio term;
	size_t code_length;
	struct iovec io;
	int status;
	char* endp;
	pid_t pid;

	if (argc != 2)
		usage();

	pid = strtol(argv[1], &endp, 10);
	if (*endp != '\0')
		usage();

	assert(ioctl(0, TCGETA, &term) == 0);

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		perror("PTRACE_ATTACH");
		return 1;
	}

	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid");
		return 1;
	}

	io.iov_base = &regs;
	io.iov_len = sizeof(regs);
	if (ptrace(PTRACE_GETREGSET, pid, 1, &io) == -1) {
		perror("PTRACE_GETREGS");
		return 1;
	}

	printf("Attached, registers contents:\n");

#define PRINTREG(REG) \
	printf("Register: " #REG " - %x\n", regs.REG);

	PRINTREG(eax);
	PRINTREG(ebx);
	PRINTREG(ecx);
	PRINTREG(edx);
	PRINTREG(eip);
	PRINTREG(esp);


 	code_length = &&code_end - &&code_start;
	regs.eip = WORD_ROUND((unsigned)regs.eip);
	term_address = regs.eip + WORD_ROUND(code_length);
	hw_address = term_address + WORD_ROUND(sizeof(term));
	hw_len = sizeof(hello_world) - 1;

	if (poke_data(pid, regs.eip, &&code_start, code_length))
		return 1;

	if (poke_data(pid, term_address, (unsigned int*)&term, sizeof(term)))
		return 1;

	if (poke_data(pid, hw_address, (unsigned int*)hello_world, sizeof(hello_world) - 1))
		return 1;

	if (poke_data(pid, regs.eip + 2 * 4, &term_address, sizeof(term_address)))
		return 1;

	if (poke_data(pid, regs.eip + 3 * 4, &hw_address, sizeof(hw_address)))
		return 1;

	if (poke_data(pid, regs.eip + 4 * 4, &hw_len, sizeof(hw_len)))
		return 1;

	if (ptrace(PTRACE_SETREGSET, pid, 1, &io) == -1) {
		perror("PTRACE_SETREGS");
		return 1;
	}

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		perror("PTRACE_CONT");
		return 1;
	}
	
	if (rand() + 1) 
		return 0;

code_start:

/*code to inject to infested process*/

	asm volatile ("	 		\
		call code;		\
/*add some bytes so that stubs begin at word boundary ('call code' is 5 bytes long)*/	\
.byte		0x0, 0x0, 0x0;		\
/*stubs for addresses of termios, hello_word string and its length*/ \
.byte		0x0, 0x0, 0x0, 0x0, 0x0;\
.byte		0x0, 0x0, 0x0, 0x0, 0x0;\
.byte		0x0, 0x0, 0x0, 0x0, 0x0;\
code:					\
/*get address of first stub*/		\
		pop %%esi;		\
		addl $3, %%esi;		\
/*setup sane termios*/			\
		movl $0x36, %%eax;  	\
		movl $0x0, %%ebx;	\
		movl $0x5407, %%ecx;	\
		movl (%%esi), %%edx;	\
		int $0x80; 	 	\
/*write our string*/			\
		movl $0x4, %%eax;  	\
		movl $0x1, %%ebx;  	\
		movl 0x4(%%esi), %%ecx;	\
		movl 0x8(%%esi), %%edx;	\
		int $0x80; 	 	\
/*bye*/					\
		movl $252, %%eax;  	\
		int $0x80; 		\
		" : : : "eax", "ebx", "ecx", "edx", "esi", "edi" );
code_end:

	return 0;
}
