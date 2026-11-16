"""Small, deliberately limited DNS master-file reader.

Supported syntax per non-comment line:
owner [TTL] IN TYPE RDATA
Examples:
@ 300 IN A 192.0.2.10
www 300 IN CNAME example.test.
@ 300 IN MX 10 mail.example.test.
This is a teaching subset, not a complete BIND master-file parser.
"""
from __future__ import annotations
from pathlib import Path
from .packet import DNSRecord
from .records import TYPE_TO_CODE

class Zone:
    def __init__(self, origin: str, records=None):
        self.origin = origin.rstrip(".").lower() + "."
        self.records = list(records or [])

    def absolute_name(self, owner: str) -> str:
        owner = owner.strip()
        if owner == "@": return self.origin
        if owner.endswith("."): return owner.lower()
        return (owner + "." + self.origin).lower()

    @classmethod
    def from_file(cls, path, origin: str):
        zone = cls(origin)
        for line_no, raw in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            line = raw.split(";", 1)[0].strip()
            if not line: continue
            parts = line.split()
            if len(parts) < 4: raise ValueError(f"Zone line {line_no}: expected owner [TTL] IN TYPE RDATA")
            owner = parts.pop(0)
            ttl = 300
            if parts and parts[0].isdigit(): ttl = int(parts.pop(0))
            if not parts or parts.pop(0).upper() != "IN":
                raise ValueError(f"Zone line {line_no}: only class IN is supported")
            if len(parts) < 2: raise ValueError(f"Zone line {line_no}: missing type or RDATA")
            rtype = parts.pop(0).upper()
            if rtype not in TYPE_TO_CODE: raise ValueError(f"Zone line {line_no}: unsupported type {rtype}")
            value = " ".join(parts)
            if rtype in ("NS", "CNAME"):
                value = zone.absolute_name(value)
            elif rtype == "MX":
                pref, exchange = value.split(None, 1)
                value = f"{int(pref)} {zone.absolute_name(exchange)}"
            zone.records.append(DNSRecord(zone.absolute_name(owner), rtype, value, ttl))
        return zone

    def lookup(self, name: str, qtype: str):
        name = name.rstrip(".").lower() + "."
        qtype = qtype.upper()
        exact = [r for r in self.records if r.name.rstrip(".").lower() + "." == name]
        if qtype == "ANY": return exact
        direct = [r for r in exact if r.rtype == qtype]
        if direct: return direct
        # A CNAME answer is useful when the requested owner is an alias.
        return [r for r in exact if r.rtype == "CNAME"]

    def is_in_zone(self, name: str) -> bool:
        name = name.rstrip(".").lower() + "."
        return name == self.origin or name.endswith("." + self.origin)

    def has_name(self, name: str) -> bool:
        name = name.rstrip(".").lower() + "."
        return any(r.name.rstrip(".").lower() + "." == name for r in self.records)
