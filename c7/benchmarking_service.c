#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/mman.h>

void init() 
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  //alarm(3);
}

void load_jail()
{
  scmp_filter_ctx ctx;

  ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
  seccomp_load(ctx);
}

int main(int argc, char const *argv[])
{
  unsigned char *code;
  void (*shellcode)(void); 

  init();
  code = (unsigned char *) mmap(NULL, 1024, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  load_jail();
  read(0, code, 1024);
  shellcode = (void (*)())code;
  shellcode();
  return 0;
}