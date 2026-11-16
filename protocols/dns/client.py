"""DNS client for this project's supported record types."""
from __future__ import annotations
import socket, struct, time
from .packet import build_query, parse_message

class DNSClient:
    def __init__(self, server="127.0.0.1", port=10053, timeout=2.0):
        self.server, self.port, self.timeout = server, port, timeout

    def query(self, name: str, qtype="A", tcp=False):
        request = build_query(name, qtype)
        start = time.perf_counter()
        if tcp:
            with socket.create_connection((self.server, self.port), self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(struct.pack("!H", len(request)) + request)
                header = self._recv_exact(s, 2)
                size = struct.unpack("!H", header)[0]
                response = self._recv_exact(s, size)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout)
                s.sendto(request, (self.server, self.port))
                response, _ = s.recvfrom(65535)
        elapsed_ms = (time.perf_counter() - start) * 1000
        message = parse_message(response)
        if message.ident != int.from_bytes(request[:2], "big"):
            raise ValueError("DNS transaction ID mismatch")
        if message.truncated and not tcp:
            return self.query(name, qtype, tcp=True)
        return message, elapsed_ms

    @staticmethod
    def _recv_exact(sock, size):
        chunks = bytearray()
        while len(chunks) < size:
            part = sock.recv(size - len(chunks))
            if not part: raise OSError("TCP connection closed mid-message")
            chunks.extend(part)
        return bytes(chunks)

def main():
    import argparse
    p = argparse.ArgumentParser(description="Query the project's DNS server")
    p.add_argument("name")
    p.add_argument("--type", default="A", choices=["A", "AAAA", "MX", "CNAME", "NS"])
    p.add_argument("--server", default="127.0.0.1")
    p.add_argument("--port", type=int, default=10053)
    p.add_argument("--tcp", action="store_true")
    a = p.parse_args()
    message, elapsed = DNSClient(a.server, a.port).query(a.name, a.type, a.tcp)
    print(f"RCODE={message.rcode} ({['NOERROR','FORMERR','SERVFAIL','NXDOMAIN'][message.rcode] if message.rcode < 4 else message.rcode})")
    print(f"Response time: {elapsed:.3f} ms")
    for rr in message.answers:
        print(f"{rr.name} {rr.ttl} IN {rr.rtype} {rr.value}")
    if not message.answers: print("(no answer records)")

if __name__ == "__main__": main()
