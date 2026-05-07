"""
agent.py — IDS Agent
====================
This is the file that OTHER PEOPLE download and run on their laptop.

When they run this:
  1. It captures THEIR real network traffic
  2. Sends it to YOUR website's backend
  3. Their traffic shows up on the dashboard in real time

How to run:
    python agent.py --server wss://your-ids-backend.onrender.com/agent

Or for local testing:
    python agent.py --server ws://localhost:8000/agent
"""

import asyncio
import json
import argparse
import platform
import uuid
import time
import random
import socket
from datetime import datetime

# ── Try to import websockets ───────────────────────────────────────────────
try:
    import websockets
except ImportError:
    print("[!] Missing library. Run this first:")
    print("    pip install websockets scapy")
    exit(1)

# ── Try to import Scapy for REAL packet capture ────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
    print("[✓] Scapy found — will capture REAL network packets")
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not found — using simulated traffic")
    print("    For real capture, run:  pip install scapy")

# ── Each agent gets a unique ID (so server knows which laptop it is) ───────
AGENT_ID   = str(uuid.uuid4())[:8]
DEVICE_NAME = platform.node() or "Unknown Device"
OS_NAME     = platform.system() + " " + platform.release()

print(f"\n{'='*50}")
print(f"  AI-IDS Agent")
print(f"  Device : {DEVICE_NAME}")
print(f"  OS     : {OS_NAME}")
print(f"  ID     : {AGENT_ID}")
print(f"{'='*50}\n")


# ── Main agent class ───────────────────────────────────────────────────────
class IDSAgent:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.ws         = None
        self.running    = False
        self.packet_queue = asyncio.Queue()

    async def connect(self):
        """Keep trying to connect to the server."""
        while True:
            try:
                print(f"[*] Connecting to {self.server_url} ...")
                async with websockets.connect(self.server_url) as ws:
                    self.ws = ws
                    self.running = True
                    print(f"[✓] Connected! Your traffic is now being monitored.")
                    print(f"    Open the dashboard to see your alerts.\n")

                    # Send registration message first
                    await ws.send(json.dumps({
                        "type":        "register",
                        "agent_id":    AGENT_ID,
                        "device_name": DEVICE_NAME,
                        "os":          OS_NAME,
                        "timestamp":   datetime.now().isoformat(),
                    }))

                    # Start sending packets
                    await self.send_loop(ws)

            except Exception as e:
                print(f"[!] Connection lost: {e}")
                print(f"    Retrying in 5 seconds...")
                self.running = False
                await asyncio.sleep(5)

    async def send_loop(self, ws):
        """Drain the packet queue and send to server."""
        while True:
            try:
                packet = await asyncio.wait_for(self.packet_queue.get(), timeout=1.0)
                await ws.send(json.dumps(packet))
            except asyncio.TimeoutError:
                # Send a heartbeat so server knows we're alive
                try:
                    await ws.send(json.dumps({"type": "ping", "agent_id": AGENT_ID}))
                except Exception:
                    break
            except Exception:
                break

    def enqueue_packet(self, packet_data: dict):
        """Put a captured packet into the queue (thread-safe)."""
        try:
            self.packet_queue.put_nowait({
                "type":        "packet",
                "agent_id":    AGENT_ID,
                "device_name": DEVICE_NAME,
                **packet_data,
            })
        except asyncio.QueueFull:
            pass  # drop if queue is full (server might be slow)

    def start_capture(self):
        """Start capturing packets in a background thread."""
        if SCAPY_AVAILABLE:
            self._start_real_capture()
        else:
            asyncio.get_event_loop().create_task(self._simulate_capture())

    def _start_real_capture(self):
        """Use Scapy to capture real packets from the network interface."""
        import threading

        def capture():
            def process(pkt):
                if IP in pkt:
                    data = {
                        "src_ip":    pkt[IP].src,
                        "dst_ip":    pkt[IP].dst,
                        "protocol":  "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER"),
                        "length":    len(pkt),
                        "ttl":       pkt[IP].ttl,
                        "src_port":  pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0),
                        "dst_port":  pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0),
                        "flags":     str(pkt[TCP].flags) if TCP in pkt else "",
                        "timestamp": datetime.now().isoformat(),
                    }
                    self.enqueue_packet(data)

            print("[*] Capturing real packets... (requires admin/sudo)")
            sniff(prn=process, store=False)

        t = threading.Thread(target=capture, daemon=True)
        t.start()

    async def _simulate_capture(self):
        """Simulate realistic traffic when Scapy isn't available."""
        normal_ips  = [f"192.168.1.{i}" for i in range(2, 20)]
        attack_ips  = ["10.0.0.99", "185.220.101.5", "172.16.5.44"]
        services    = [(80,"HTTP"),(443,"HTTPS"),(22,"SSH"),(3306,"MySQL")]
        attack_svc  = [(22,"SSH"),(4444,"Metasploit"),(21,"FTP"),(3306,"MySQL")]

        # Get real local IP
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "192.168.1.100"

        while True:
            is_attack = random.random() < 0.10
            src   = random.choice(attack_ips if is_attack else normal_ips)
            port, _ = random.choice(attack_svc if is_attack else services)

            self.enqueue_packet({
                "src_ip":    src,
                "dst_ip":    local_ip,
                "protocol":  random.choice(["TCP","UDP"]),
                "length":    random.randint(40, 80) if is_attack else random.randint(100, 1400),
                "ttl":       random.randint(50, 128),
                "src_port":  random.randint(1024, 65535),
                "dst_port":  port,
                "flags":     "S" if is_attack else "PA",
                "timestamp": datetime.now().isoformat(),
            })
            await asyncio.sleep(random.uniform(0.05, 0.25))


# ── Entry point ────────────────────────────────────────────────────────────
async def main(server_url: str):
    agent = IDSAgent(server_url)
    agent.start_capture()
    await agent.connect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI-IDS Agent")
    parser.add_argument(
        "--server",
        default="ws://localhost:8000/agent",
        help="WebSocket URL of the IDS backend"
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args.server))
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")