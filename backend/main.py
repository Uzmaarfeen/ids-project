"""
main.py — AI-IDS Backend Server (Fixed for latest FastAPI)
"""

import asyncio
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from engine import IntrusionDetectionEngine

# ── Lifespan (replaces old @app.on_event which is removed in new FastAPI) ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs on startup
    thread = threading.Thread(target=lambda: asyncio.run(simulation_loop()), daemon=True)
    thread.start()
    print("\n" + "="*50)
    print("  AI-IDS Backend is RUNNING")
    print("  Open browser at: http://localhost:8000")
    print("="*50 + "\n")
    yield
    # Runs on shutdown (nothing needed)

app = FastAPI(title="AI-IDS Backend", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ──────────────────────────────────────────────────────────
engine           = IntrusionDetectionEngine()
browser_clients  = []
connected_agents = {}
alert_history    = deque(maxlen=500)
stats = {
    "total_packets":    0,
    "threats_detected": 0,
    "start_time":       time.time(),
    "active_agents":    0,
    "threat_types":     defaultdict(int),
}


# ── Broadcast to all browsers ─────────────────────────────────────────────
async def broadcast(data: dict):
    dead = []
    for ws in browser_clients:
        try:
            await ws.send_json(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in browser_clients:
            browser_clients.remove(ws)


# ── Browser WebSocket /ws ─────────────────────────────────────────────────
@app.websocket("/ws")
async def browser_ws(websocket: WebSocket):
    await websocket.accept()
    browser_clients.append(websocket)
    await websocket.send_json({
        "type":   "init",
        "alerts": list(alert_history),
        "stats":  {**stats, "threat_types": dict(stats["threat_types"])},
        "agents": [{"agent_id": aid, **info} for aid, info in connected_agents.items()],
    })
    try:
        while True:
            await asyncio.sleep(5)
            await websocket.send_json({
                "type":  "stats",
                "stats": {**stats, "threat_types": dict(stats["threat_types"])},
                "agents": [{"agent_id": aid, **info} for aid, info in connected_agents.items()],
            })
    except WebSocketDisconnect:
        if websocket in browser_clients:
            browser_clients.remove(websocket)


# ── Agent WebSocket /agent ────────────────────────────────────────────────
@app.websocket("/agent")
async def agent_ws(websocket: WebSocket):
    await websocket.accept()
    agent_id = None
    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)

            if msg.get("type") == "register":
                agent_id = msg["agent_id"]
                connected_agents[agent_id] = {
                    "device_name":  msg.get("device_name", "Unknown"),
                    "os":           msg.get("os", "Unknown"),
                    "connected_at": datetime.now().isoformat(),
                    "packet_count": 0,
                }
                stats["active_agents"] = len(connected_agents)
                print(f"[+] Agent connected: {msg.get('device_name')} ({agent_id})")
                await broadcast({"type": "agent_connected", "agent_id": agent_id,
                                 "device_name": msg.get("device_name"), "os": msg.get("os")})

            elif msg.get("type") == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))

            elif msg.get("type") == "packet":
                packet = {k: v for k, v in msg.items() if k != "type"}
                stats["total_packets"] += 1
                if agent_id in connected_agents:
                    connected_agents[agent_id]["packet_count"] += 1

                result = engine.analyze(packet)
                packet["analysis"] = result

                event = {
                    "type": "packet", "agent_id": agent_id,
                    "device": connected_agents.get(agent_id, {}).get("device_name", "Unknown"),
                    "data": packet, "is_threat": result["is_threat"],
                    "stats": {"total_packets": stats["total_packets"],
                              "threats_detected": stats["threats_detected"],
                              "active_agents": stats["active_agents"]},
                }

                if result["is_threat"]:
                    stats["threats_detected"] += 1
                    stats["threat_types"][result["threat_type"]] += 1
                    alert = {
                        "id": stats["threats_detected"],
                        "timestamp": packet.get("timestamp", datetime.now().isoformat()),
                        "agent_id": agent_id,
                        "device": connected_agents.get(agent_id, {}).get("device_name", "Unknown"),
                        "src_ip": packet.get("src_ip", ""), "dst_ip": packet.get("dst_ip", ""),
                        "threat_type": result["threat_type"], "severity": result["severity"],
                        "confidence": result["confidence"], "description": result["description"],
                        "protocol": packet.get("protocol", ""), "dst_port": packet.get("dst_port", 0),
                    }
                    alert_history.append(alert)
                    event["alert"] = alert

                await broadcast(event)

    except Exception:
        if agent_id and agent_id in connected_agents:
            del connected_agents[agent_id]
            stats["active_agents"] = len(connected_agents)
            await broadcast({"type": "agent_disconnected", "agent_id": agent_id})


# ── Simulation (runs when no real agent is connected, for demo) ───────────
async def simulation_loop():
    import random, socket
    normal_ips = [f"192.168.1.{i}" for i in range(2, 20)]
    attack_ips = ["10.0.0.99", "185.220.101.5", "172.16.5.44"]
    services   = [(80,"HTTP"),(443,"HTTPS"),(22,"SSH"),(3306,"MySQL")]
    attack_svc = [(22,"SSH"),(4444,"Metasploit"),(21,"FTP"),(3306,"MySQL")]

    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        local_ip = "192.168.1.100"

    SIM_AGENT_ID = "demo-sim"
    connected_agents[SIM_AGENT_ID] = {
        "device_name": "Demo Simulation",
        "os": "Simulated Traffic",
        "connected_at": datetime.now().isoformat(),
        "packet_count": 0,
    }
    stats["active_agents"] = len(connected_agents)

    while True:
        is_attack = random.random() < 0.10
        src   = random.choice(attack_ips if is_attack else normal_ips)
        port, _ = random.choice(attack_svc if is_attack else services)

        packet = {
            "src_ip":    src,
            "dst_ip":    local_ip,
            "protocol":  random.choice(["TCP","UDP"]),
            "length":    random.randint(40, 80) if is_attack else random.randint(100, 1400),
            "ttl":       random.randint(50, 128),
            "src_port":  random.randint(1024, 65535),
            "dst_port":  port,
            "flags":     "S" if is_attack else "PA",
            "timestamp": datetime.now().isoformat(),
        }

        stats["total_packets"] += 1
        connected_agents[SIM_AGENT_ID]["packet_count"] += 1

        result = engine.analyze(packet)
        packet["analysis"] = result

        event = {
            "type": "packet", "agent_id": SIM_AGENT_ID,
            "device": "Demo Simulation",
            "data": packet, "is_threat": result["is_threat"],
            "stats": {"total_packets": stats["total_packets"],
                      "threats_detected": stats["threats_detected"],
                      "active_agents": stats["active_agents"]},
        }

        if result["is_threat"]:
            stats["threats_detected"] += 1
            stats["threat_types"][result["threat_type"]] += 1
            alert = {
                "id": stats["threats_detected"],
                "timestamp": packet["timestamp"],
                "agent_id": SIM_AGENT_ID,
                "device": "Demo Simulation",
                "src_ip": packet["src_ip"], "dst_ip": packet["dst_ip"],
                "threat_type": result["threat_type"], "severity": result["severity"],
                "confidence": result["confidence"], "description": result["description"],
                "protocol": packet["protocol"], "dst_port": packet["dst_port"],
            }
            alert_history.append(alert)
            event["alert"] = alert

        await broadcast(event)
        await asyncio.sleep(random.uniform(0.1, 0.3))


# ── REST endpoints ────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    return {**stats, "threat_types": dict(stats["threat_types"])}

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return list(alert_history)[-limit:]

@app.get("/api/agents")
def get_agents():
    return [{"agent_id": k, **v} for k, v in connected_agents.items()]

@app.get("/api/health")
def health():
    return {"status": "running", "uptime": int(time.time() - stats["start_time"])}

@app.get("/")
def serve_dashboard():
    import os
    # Try multiple possible paths
    base = os.path.dirname(os.path.abspath(__file__))
    paths_to_try = [
        os.path.join(base, "..", "frontend", "index.html"),
        os.path.join(base, "frontend", "index.html"),
        os.path.join("frontend", "index.html"),
        "frontend/index.html",
    ]
    for p in paths_to_try:
        if os.path.exists(p):
            print(f"[*] Serving: {os.path.abspath(p)}")
            return FileResponse(p)
    # If still not found, return helpful error
    from fastapi.responses import HTMLResponse
    return HTMLResponse(f"""
    <h2 style='font-family:monospace;color:red'>index.html not found!</h2>
    <p style='font-family:monospace'>Backend is running ✓ but cannot find frontend/index.html</p>
    <p style='font-family:monospace'>Looked in: {[os.path.abspath(p) for p in paths_to_try]}</p>
    <p style='font-family:monospace'>Your backend folder is at: {base}</p>
    """)

@app.get("/download-agent")
def download_agent():
    import os
    base = os.path.dirname(os.path.abspath(__file__))
    paths_to_try = [
        os.path.join(base, "..", "agent", "agent.py"),
        os.path.join(base, "agent", "agent.py"),
        "agent/agent.py",
    ]
    for p in paths_to_try:
        if os.path.exists(p):
            return FileResponse(p, media_type="text/plain", filename="agent.py")
    from fastapi.responses import JSONResponse
    return JSONResponse({"error": "agent.py not found"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)