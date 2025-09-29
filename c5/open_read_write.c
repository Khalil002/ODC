#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include "seccomp-bpf.h"

static int install_syscall_filter(void)
{
  struct sock_filter filter[] = {
    /* Validate architecture. */
    VALIDATE_ARCHITECTURE,
    /* Grab the system call number. */
    EXAMINE_SYSCALL,
    /* List allowed syscalls. */
    ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
    ALLOW_SYSCALL(sigreturn),
#endif
    ALLOW_SYSCALL(exit_group),
    ALLOW_SYSCALL(exit),
    ALLOW_SYSCALL(read),
    ALLOW_SYSCALL(write),
    ALLOW_SYSCALL(open),
    KILL_PROCESS,
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
    .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    goto failed;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(SECCOMP)");
    goto failed;
  }
  return 0;

failed:
  if (errno == EINVAL)
    fprintf(stderr, "SECCOMP_FILTER is not available. :(\n");
  return 1;
}

int main(){
  void *data;
  alarm(2);
  data = mmap(0, 0x1000, 7, 0x22, -1, 0);
  if (install_syscall_filter())
    return 1;
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  printf("  _________.__           .__  .__                   .___      \n /   _____/|  |__   ____ |  | |  |   ____  ____   __| _/____  \n \\_____  \\ |  |  \\_/ __ \\|  | |  | _/ ___\\/  _ \\ / __ |/ __ \\ \n /        \\|   Y  \\  ___/|  |_|  |_\\  \\__(  <_> ) /_/ \\  ___/ \n/_______  /|___|  /\\___  >____/____/\\___  >____/\\____ |\\___  >\n        \\/      \\/     \\/               \\/           \\/    \\/ \n\n\n\n");
  read(0, data, 0x200);
  printf("Executing your shellcode.");
  register long rax __asm__("rax") = data;
  asm("jmp %rax");

}
