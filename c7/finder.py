import os
import subprocess

# Basic usage



os.environ["PYTHONUNBUFFERED"] = "1"
result = subprocess.run(['python3', 'c7/wrapper.py'], 
                        env={'PYTHONUNBUFFERED': '1'},
                        capture_output=True, text=True)
print("Return code:", result.returncode)
print("Output:", result.stdout)
print("Errors:", result.stderr)