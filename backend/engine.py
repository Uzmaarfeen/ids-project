"""
engine.py — AI Intrusion Detection Engine
==========================================
This is the BRAIN of the system. It analyses each packet and decides
whether it is normal traffic or a threat.

Techniques used (mention these in your placement interview!):
  - Rule-based detection  (fast, catches known attacks)
  - Statistical anomaly detection  (catches unusual behaviour)
  - Port scan detection   (tracks connections per IP)
  - Brute-force detection (counts repeated attempts)
  - Payload size analysis (large/tiny packets can signal attacks)
"""

import time
import math
from collections import defaultdict, deque


class IntrusionDetectionEngine:
    """
    Multi-layered detection engine.

    In a production system this would load a trained ML model
    (e.g. RandomForest or LSTM) from a .pkl file. The architecture
    here is designed so you can drop in a real model easily.
    """

    def __init__(self):
        # Track connection attempts per source IP (for port scan / brute force)
        self.ip_connections:   dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.ip_port_history:  dict[str, set]   = defaultdict(set)
        self.ip_packet_sizes:  dict[str, list]  = defaultdict(list)
        self.ip_fail_count:    dict[str, int]   = defaultdict(int)

        # Known attack signatures (simplified — real IDS uses Snort rules)
        self.suspicious_ports = {
            4444: ("Metasploit",    "CRITICAL"),
            1337: ("Backdoor",      "CRITICAL"),
            31337: ("Elite hacker", "CRITICAL"),
            5900: ("VNC Remote",    "HIGH"),
            23:   ("Telnet",        "HIGH"),
            512:  ("RSH",           "HIGH"),
            513:  ("Rlogin",        "HIGH"),
            6667: ("IRC Botnet",    "HIGH"),
            8080: ("Alt HTTP",      "MEDIUM"),
            3389: ("RDP",           "MEDIUM"),
        }

        self.private_ranges = [
            ("192.168.0.0", "192.168.255.255"),
            ("10.0.0.0",    "10.255.255.255"),
            ("172.16.0.0",  "172.31.255.255"),
        ]

    # ── Public API ─────────────────────────────────────────────────────────────
    def analyze(self, packet: dict) -> dict:
        """
        Analyse a single packet. Returns a result dict with:
          - is_threat   (bool)
          - threat_type (str)
          - severity    (str: CRITICAL / HIGH / MEDIUM / LOW)
          - confidence  (float: 0.0 – 1.0)
          - description (str)
          - features    (dict — the extracted features, for the ML layer)
        """
        src_ip   = packet.get("src_ip", "")
        dst_port = int(packet.get("dst_port", 0))
        protocol = packet.get("protocol", "TCP")
        length   = int(packet.get("length", 0))
        flags    = packet.get("flags", "")
        ttl      = int(packet.get("ttl", 64))

        now = time.time()
        self.ip_connections[src_ip].append(now)
        self.ip_port_history[src_ip].add(dst_port)
        self.ip_packet_sizes[src_ip].append(length)

        # Extract features (these would be fed into a trained ML model)
        features = self._extract_features(src_ip, dst_port, length, ttl, flags, now)

        # ── Detection layers ──────────────────────────────────────────────────

        # 1. Known bad port
        if dst_port in self.suspicious_ports:
            name, severity = self.suspicious_ports[dst_port]
            return self._threat(
                threat_type  = name,
                severity     = severity,
                confidence   = 0.95,
                description  = f"Connection to known malicious port {dst_port} ({name})",
                features     = features,
            )

        # 2. Port scan detection (>15 unique ports from same IP in 10 s)
        recent = [t for t in self.ip_connections[src_ip] if now - t < 10]
        unique_ports = len(self.ip_port_history[src_ip])
        if len(recent) > 15 and unique_ports > 10:
            return self._threat(
                threat_type  = "Port Scan",
                severity     = "HIGH",
                confidence   = min(0.95, len(recent) / 30),
                description  = f"Scanning {unique_ports} ports — {len(recent)} packets in 10 s",
                features     = features,
            )

        # 3. Brute-force detection (SSH/FTP with tiny packets = login attempts)
        if dst_port in (22, 21, 23, 3306) and length < 80:
            self.ip_fail_count[src_ip] += 1
            if self.ip_fail_count[src_ip] > 5:
                service = {22:"SSH", 21:"FTP", 23:"Telnet", 3306:"MySQL"}.get(dst_port,"")
                return self._threat(
                    threat_type  = f"{service} Brute Force",
                    severity     = "HIGH",
                    confidence   = min(0.99, self.ip_fail_count[src_ip] / 20),
                    description  = f"{self.ip_fail_count[src_ip]} repeated {service} attempts from {src_ip}",
                    features     = features,
                )

        # 4. SYN flood (many SYN-only packets, no ACK)
        if flags == "S" and len(recent) > 20:
            return self._threat(
                threat_type  = "SYN Flood DDoS",
                severity     = "CRITICAL",
                confidence   = 0.90,
                description  = f"SYN flood detected — {len(recent)} SYN packets in 10 s",
                features     = features,
            )

        # 5. Anomaly: abnormal packet size for protocol
        avg_size = self._moving_average(self.ip_packet_sizes[src_ip])
        if avg_size and abs(length - avg_size) > 3 * self._std_dev(self.ip_packet_sizes[src_ip]):
            if length > 1400:
                return self._threat(
                    threat_type  = "Large Payload Anomaly",
                    severity     = "MEDIUM",
                    confidence   = 0.70,
                    description  = f"Unusually large packet ({length} bytes) from {src_ip}",
                    features     = features,
                )

        # 6. Suspicious TTL (could indicate OS fingerprinting or spoofing)
        if ttl < 10:
            return self._threat(
                threat_type  = "TTL Anomaly",
                severity     = "MEDIUM",
                confidence   = 0.65,
                description  = f"Abnormally low TTL ({ttl}) — possible spoofing or traceroute",
                features     = features,
            )

        # All checks passed — normal traffic
        return {
            "is_threat":   False,
            "threat_type": "None",
            "severity":    "SAFE",
            "confidence":  0.0,
            "description": "Normal traffic",
            "features":    features,
        }

    # ── Private helpers ────────────────────────────────────────────────────────
    def _threat(self, threat_type, severity, confidence, description, features):
        return {
            "is_threat":   True,
            "threat_type": threat_type,
            "severity":    severity,
            "confidence":  round(confidence, 3),
            "description": description,
            "features":    features,
        }

    def _extract_features(self, src_ip, dst_port, length, ttl, flags, now):
        """
        Feature vector — this is what you'd pass to a trained ML model.
        Mention this in interviews: 'We extract 8 features per packet
        and feed them into our detection model.'
        """
        recent = [t for t in self.ip_connections[src_ip] if now - t < 10]
        return {
            "packet_rate_10s":    len(recent),
            "unique_ports":       len(self.ip_port_history[src_ip]),
            "avg_packet_size":    round(self._moving_average(self.ip_packet_sizes[src_ip]), 1),
            "dst_port":           dst_port,
            "packet_length":      length,
            "ttl":                ttl,
            "is_syn_only":        int(flags == "S"),
            "repeated_attempts":  self.ip_fail_count[src_ip],
        }

    @staticmethod
    def _moving_average(values: list) -> float:
        if not values:
            return 0.0
        recent = values[-20:]
        return sum(recent) / len(recent)

    @staticmethod
    def _std_dev(values: list) -> float:
        if len(values) < 2:
            return 0.0
        recent = values[-20:]
        avg = sum(recent) / len(recent)
        variance = sum((x - avg) ** 2 for x in recent) / len(recent)
        return math.sqrt(variance)
