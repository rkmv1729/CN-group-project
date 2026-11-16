"""DNS resource-record constants and RDATA encoding/decoding helpers.

Supported record types: A, NS, CNAME, MX, AAAA.
The wire format follows RFC 1035; AAAA uses the IPv6 address format.
"""
from __future__ import annotations
import ipaddress
import struct

TYPE_TO_CODE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "AAAA": 28}
CODE_TO_TYPE = {v: k for k, v in TYPE_TO_CODE.items()}
CLASS_IN = 1

def encode_rdata(rr_type: str, value: str) -> bytes:
    t = rr_type.upper()
    if t == "A":
        return ipaddress.IPv4Address(value).packed
    if t == "AAAA":
        return ipaddress.IPv6Address(value).packed
    if t in ("NS", "CNAME"):
        # The packet encoder replaces this marker with a DNS-encoded name.
        # Kept here as UTF-8 text for the zone model; packet.py handles wire encoding.
        return value.rstrip(".").encode("ascii")
    if t == "MX":
        preference, exchange = value.split(None, 1)
        pref = int(preference)
        if not 0 <= pref <= 65535:
            raise ValueError("MX preference must fit in 16 bits")
        return struct.pack("!H", pref) + exchange.rstrip(".").encode("ascii")
    raise ValueError(f"Unsupported DNS record type: {rr_type}")

def decode_rdata(rr_type: str, data: bytes, packet: bytes, rdata_offset: int):
    t = rr_type.upper()
    if t == "A":
        if len(data) != 4: raise ValueError("A RDATA must be exactly 4 bytes")
        return str(ipaddress.IPv4Address(data))
    if t == "AAAA":
        if len(data) != 16: raise ValueError("AAAA RDATA must be exactly 16 bytes")
        return str(ipaddress.IPv6Address(data))
    if t in ("NS", "CNAME"):
        from .packet import decode_name
        name, _ = decode_name(packet, rdata_offset)
        return name
    if t == "MX":
        if len(data) < 3: raise ValueError("MX RDATA is too short")
        pref = struct.unpack("!H", data[:2])[0]
        from .packet import decode_name
        exchange, _ = decode_name(packet, rdata_offset + 2)
        return f"{pref} {exchange}"
    return data.hex()
