import subprocess

# Basic command
result = subprocess.run(['dir'], shell=True, capture_output=True, text=True)
print(result.stdout)

# With error handling
result = subprocess.run(
    ['ping', 'google.com'],
    capture_output=True,
    text=True,
    timeout=10
)
if result.returncode == 0:
    print("Success!")
    print(result.stdout)
else:
    print(f"Error: {result.stderr}")