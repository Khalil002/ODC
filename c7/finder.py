import os
import subprocess

# Basic usage



os.environ["PYTHONUNBUFFERED"] = "1"
result = subprocess.run(['python3', 'wrapper.py'], 
                        env={'PYTHONUNBUFFERED': '1'},
                        capture_output=True, text=True)
print("Return code:", result.returncode)
print("Output:", result.stdout)
time_str = result.output.split("Time: ")[1].strip()
time_val = float(time_str)
print(f"Time: {time_val}")
print("Errors:", result.stderr)