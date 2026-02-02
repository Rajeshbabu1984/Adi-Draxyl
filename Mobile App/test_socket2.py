import socket
import time
import subprocess

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 5002))
    sock.listen(1)
    print("✅ Successfully bound to port 5002")
    print("Running netstat...")
    result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if '5002' in line:
            print(line)
    print("Listening for 10 seconds...")
    time.sleep(10)
    sock.close()
    print("Closed socket")
except Exception as e:
    print(f"❌ Error: {e}")
