"""Local authoritative DNS server over UDP and TCP."""
from __future__ import annotations
import socket, struct, threading
from datetime import datetime, timezone
from .packet import DNSMessage, DNSRecord, parse_message, encode_message, RCODE
from .zone import Zone

class DNSServer:
    def __init__(self, zone: Zone, host="127.0.0.1", port=10053, udp_limit=512,
                 upstream=None, upstream_timeout=2.0, on_packet_callback=None):
        self.zone, self.host, self.port = zone, host, port
        self.udp_limit = udp_limit
        self.upstream = upstream  # (host, port), e.g. ("1.1.1.1", 53); None disables forwarding
        self.upstream_timeout = upstream_timeout
        self.on_packet_callback = on_packet_callback
        self._stop = threading.Event()
        self._sockets = []

    def handle_query(self, data: bytes, transport="udp") -> bytes:
        try:
            query = parse_message(data)
            if query.is_response or not query.questions:
                raise ValueError("Expected a DNS query containing at least one question")
            q = query.questions[0]
            # Names outside this server's configured zone may be forwarded if
            # an upstream resolver was explicitly configured.
            if not self.zone.is_in_zone(q.name):
                if self.upstream:
                    try:
                        return self._forward(data)
                    except OSError:
                        flags = 0x8000 | (query.flags & 0x0100)
                        return encode_message(DNSMessage(query.ident, flags | RCODE["SERVFAIL"], [q]))
                # This server is not authoritative for names outside its zone.
                flags = 0x8000 | (query.flags & 0x0100)
                return encode_message(DNSMessage(query.ident, flags | RCODE["REFUSED"], [q]))
            answers = self.zone.lookup(q.name, q.qtype)
            if answers:
                flags = 0x8000 | 0x0400 | (query.flags & 0x0100)  # QR, AA, preserve RD
                rcode = RCODE["NOERROR"]
            else:
                flags = 0x8000 | 0x0400 | (query.flags & 0x0100)
                rcode = RCODE["NXDOMAIN"] if not self.zone.has_name(q.name) else RCODE["NOERROR"]
            response = DNSMessage(query.ident, flags | rcode, [q], answers)
            encoded = encode_message(response)
            if transport.lower() == "udp" and len(encoded) > self.udp_limit:
                # This educational server truncates by omitting answer RRs and setting TC.
                response.answers = []
                response.flags |= 0x0200
                encoded = encode_message(response)
            return encoded
        except Exception:
            # FORMERR response where transaction ID can be recovered.
            ident = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
            return encode_message(DNSMessage(ident, 0x8000 | RCODE["FORMERR"]))

    def _forward(self, request: bytes) -> bytes:
        """Forward one DNS message to a configured upstream resolver.

        Use UDP first. If the upstream response is truncated, retry over TCP
        using DNS's two-byte length prefix.
        """
        host, port = self.upstream
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
            upstream_sock.settimeout(self.upstream_timeout)
            upstream_sock.sendto(request, (host, port))
            response, _ = upstream_sock.recvfrom(65535)
        try:
            parsed = parse_message(response)
            if not parsed.truncated:
                return response
        except ValueError:
            return response
        with socket.create_connection((host, port), self.upstream_timeout) as conn:
            conn.settimeout(self.upstream_timeout)
            conn.sendall(struct.pack("!H", len(request)) + request)
            size = struct.unpack("!H", self._recv_exact(conn, 2))[0]
            return self._recv_exact(conn, size)

    def _emit_packet(self, packet_type, raw, source, destination):
        """Send a decoded packet event to the shared logger callback."""
        if self.on_packet_callback is None:
            return
        try:
            try:
                message = parse_message(raw)
                details = {
                    "id": message.ident,
                    "flags": message.flags,
                    "rcode": message.rcode,
                    "questions": [
                        {"name": q.name, "type": q.qtype, "class": q.qclass}
                        for q in message.questions
                    ],
                    "answers": [
                        {"name": r.name, "type": r.rtype, "value": r.value, "ttl": r.ttl}
                        for r in message.answers
                    ],
                }
            except Exception as exc:
                details = {"decode_error": str(exc)}
            self.on_packet_callback({
                "type": packet_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": {"ip": str(source[0]), "port": int(source[1])},
                "destination": {"ip": str(destination[0]), "port": int(destination[1])},
                "raw_hex": raw.hex(),
                "packet": details,
            })
        except Exception:
            # Packet logging must never bring down DNS service.
            pass

    def serve_udp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port)); s.settimeout(0.5); self._sockets.append(s)
        while not self._stop.is_set():
            try: data, addr = s.recvfrom(65535)
            except socket.timeout: continue
            except OSError: break
            response = self.handle_query(data, transport="udp")
            local = s.getsockname()
            self._emit_packet("DNS_QUERY", data, addr, local)
            try:
                s.sendto(response, addr)
                self._emit_packet("DNS_RESPONSE", response, local, addr)
            except OSError:
                break
        s.close()

    def serve_tcp(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port)); s.listen(10); s.settimeout(0.5); self._sockets.append(s)
        while not self._stop.is_set():
            try: conn, addr = s.accept()
            except socket.timeout: continue
            except OSError: break
            with conn:
                try:
                    header = self._recv_exact(conn, 2)
                    size = struct.unpack("!H", header)[0]
                    data = self._recv_exact(conn, size)
                    response = self.handle_query(data, transport="tcp")
                    local = conn.getsockname()
                    self._emit_packet("DNS_QUERY", data, addr, local)
                    conn.sendall(struct.pack("!H", len(response)) + response)
                    self._emit_packet("DNS_RESPONSE", response, local, addr)
                except (OSError, ValueError):
                    continue
        s.close()

    @staticmethod
    def _recv_exact(conn, size):
        chunks = bytearray()
        while len(chunks) < size:
            part = conn.recv(size - len(chunks))
            if not part: raise OSError("TCP connection closed mid-message")
            chunks.extend(part)
        return bytes(chunks)

    def start(self, tcp=True):
        self._stop.clear()
        threads = [threading.Thread(target=self.serve_udp, daemon=True)]
        if tcp: threads.append(threading.Thread(target=self.serve_tcp, daemon=True))
        for t in threads: t.start()
        return threads

    def stop(self):
        self._stop.set()
        for s in self._sockets:
            try: s.close()
            except OSError: pass

def main():
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Run the educational local DNS server")
    parser.add_argument("--zone", default="data/zone.txt")
    parser.add_argument("--origin", default="example.test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10053)
    parser.add_argument("--upstream", help="Optional upstream IPv4 resolver, e.g. 1.1.1.1")
    parser.add_argument("--upstream-port", type=int, default=53)
    args = parser.parse_args()
    zone = Zone.from_file(args.zone, args.origin)
    upstream = (args.upstream, args.upstream_port) if args.upstream else None
    server = DNSServer(zone, args.host, args.port, upstream=upstream)
    threads = server.start()
    print(f"DNS server listening on {args.host}:{args.port} (UDP + TCP); Ctrl+C to stop")
    try:
        while True:
            for t in threads: t.join(0.5)
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__": main()
