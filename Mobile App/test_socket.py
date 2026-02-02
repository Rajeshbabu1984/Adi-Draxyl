import socket
import time

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0', 5002))
    sock.listen(1)
    print("✅ Successfully bound to port 5002")
    print("Listening for 10 seconds...")
    time.sleep(10)
    sock.close()
    print("Closed socket")
except Exception as e:
    print(f"❌ Error: {e}")
