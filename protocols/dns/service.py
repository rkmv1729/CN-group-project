"""Integration facade intended for Roll 08's FastAPI routes.

The facade keeps HTTP concerns out of the protocol implementation. A backend
route can call start(), stop(), query(), zone_records(), and recent_logs().
"""
from __future__ import annotations
import threading
from collections import deque
from .zone import Zone
from .server import DNSServer
from .client import DNSClient

class DNSService:
    def __init__(self, zone_path="data/zone.txt", origin="example.test",
                 host="127.0.0.1", port=10053, upstream=None, on_packet_callback=None):
        self.zone_path, self.origin = zone_path, origin
        self.host, self.port = host, port
        self.upstream = upstream
        self.zone = Zone.from_file(zone_path, origin)
        self.server = DNSServer(self.zone, host, port, upstream=upstream,
                                on_packet_callback=on_packet_callback)
        self.threads = []
        self.logs = deque(maxlen=500)
        self.lock = threading.Lock()

    def start(self):
        if self.threads and any(t.is_alive() for t in self.threads):
            return {"running": True, "host": self.host, "port": self.port}
        self.threads = self.server.start(tcp=True)
        return {"running": True, "host": self.host, "port": self.port}

    def stop(self):
        self.server.stop()
        self.threads = []
        return {"running": False}

    def query(self, domain: str, record_type="A", tcp=False):
        import time
        started = time.time()
        message, elapsed_ms = DNSClient(self.host, self.port).query(domain, record_type, tcp)
        result = {
            "domain": domain, "type": record_type.upper(), "rcode": message.rcode,
            "answers": [{"name": r.name, "type": r.rtype, "value": r.value, "ttl": r.ttl}
                        for r in message.answers],
            "response_time_ms": round(elapsed_ms, 3), "transport": "tcp" if tcp else "udp",
            "timestamp": started
        }
        with self.lock: self.logs.appendleft(result)
        return result

    def zone_records(self):
        return [{"name": r.name, "type": r.rtype, "value": r.value, "ttl": r.ttl}
                for r in self.zone.records]

    def reload_zone(self):
        self.zone = Zone.from_file(self.zone_path, self.origin)
        self.server.zone = self.zone
        return self.zone_records()

    def recent_logs(self, limit=100):
        with self.lock: return list(self.logs)[:max(0, limit)]
