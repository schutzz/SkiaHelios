import socket
import time
import argparse
import sys
import random

# ============================================================
#  SkiaHelios Beacon Simulator
#  Mission: Generate Network Traffic for PlutosGate Testing
# ============================================================

def beacon_mode(target_ip, target_port, interval, count):
    print(f"[*] Starting C2 Beacon Mode -> {target_ip}:{target_port}")
    print(f"    Interval: {interval}s | Count: {count}")
    
    total_bytes = 0
    for i in range(count):
        try:
            # Connect
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((target_ip, target_port))
            
            # Send Heartbeat (Small payload)
            payload = b"HEARTBEAT_" + str(i).encode() + b"_" + b"x" * random.randint(10, 50)
            s.sendall(payload)
            total_bytes += len(payload)
            
            s.close()
            print(f"  [+] Sent Heartbeat {i+1}/{count} ({len(payload)} bytes)")
            
            time.sleep(interval)
        except Exception as e:
            print(f"  [!] Connection failed: {e}")
            # Even if failed, we try again
            time.sleep(interval)
            
    print(f"[*] Beaconing Complete. Total Sent: {total_bytes} bytes")

def exfil_mode(target_ip, target_port, size_mb):
    print(f"[*] Starting Exfiltration Mode -> {target_ip}:{target_port}")
    print(f"    Target Size: {size_mb} MB")
    
    chunk_size = 1024 * 64 # 64KB chunks
    total_bytes = 0
    target_bytes = size_mb * 1024 * 1024
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((target_ip, target_port))
        
        while total_bytes < target_bytes:
            payload = b"A" * chunk_size
            s.sendall(payload)
            total_bytes += len(payload)
            if total_bytes % (1024*1024) == 0:
                print(f"  -> Sent {total_bytes // (1024*1024)} MB...")
                
        s.close()
        print(f"[*] Exfiltration Complete. Total Sent: {total_bytes} bytes")
        
    except Exception as e:
        print(f"  [!] Exfiltration failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="SkiaHelios C2 Beacon Simulator")
    parser.add_argument("--ip", default="8.8.8.8", help="Target IP (Default: 8.8.8.8 - innocuous)")
    parser.add_argument("--port", type=int, default=443, help="Target Port")
    parser.add_argument("--mode", choices=["beacon", "exfil"], default="beacon", help="Traffic Mode")
    
    # Beacon args
    parser.add_argument("--interval", type=float, default=2.0, help="Beacon Interval (sec)")
    parser.add_argument("--count", type=int, default=5, help="Beacon Count")
    
    # Exfil args
    parser.add_argument("--size", type=int, default=50, help="Exfil Size (MB)")
    
    args = parser.parse_args()
    
    if args.mode == "beacon":
        beacon_mode(args.ip, args.port, args.interval, args.count)
    elif args.mode == "exfil":
        exfil_mode(args.ip, args.port, args.size)

if __name__ == "__main__":
    main()