"""DNS wire-format encoder/decoder.

Implements the 12-byte DNS header, question and RR sections, supported RDATA,
and RFC 1035 compression pointers. It intentionally supports a focused subset
needed by the group project, not every DNS extension.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import random
import struct
from typing import Optional
from .records import TYPE_TO_CODE, CODE_TO_TYPE, CLASS_IN, encode_rdata, decode_rdata

HEADER = struct.Struct("!HHHHHH")
QUESTION_TAIL = struct.Struct("!HH")
RR_TAIL = struct.Struct("!HHIH")
TYPE_ANY = 255
RCODE = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}
RCODE_NAME = {v: k for k, v in RCODE.items()}

@dataclass
class DNSQuestion:
    name: str
    qtype: str = "A"
    qclass: int = CLASS_IN

@dataclass
class DNSRecord:
    name: str
    rtype: str
    value: str
    ttl: int = 60
    rclass: int = CLASS_IN

@dataclass
class DNSMessage:
    ident: int = 0
    flags: int = 0
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    @property
    def is_response(self): return bool(self.flags & 0x8000)
    @property
    def rcode(self): return self.flags & 0x000F
    @property
    def truncated(self): return bool(self.flags & 0x0200)
    @property
    def recursion_desired(self): return bool(self.flags & 0x0100)

def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"
    labels = name.split(".")
    out = bytearray()
    total = 1
    for label in labels:
        raw = label.encode("idna")
        if len(raw) > 63: raise ValueError("DNS label exceeds 63 octets")
        total += 1 + len(raw)
        out.append(len(raw)); out.extend(raw)
    if total > 255: raise ValueError("DNS name exceeds 255 octets")
    out.append(0)
    return bytes(out)

def decode_name(packet: bytes, offset: int):
    """Return (decoded_name, offset_after_original_name); reject bad pointer loops."""
    labels, cursor, end_offset = [], offset, None
    visited = set()
    jumps = 0
    while True:
        if cursor >= len(packet): raise ValueError("DNS name extends beyond packet")
        length = packet[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(packet): raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[cursor + 1]
            if pointer >= len(packet): raise ValueError("Compression pointer outside packet")
            if pointer in visited: raise ValueError("Compression pointer loop")
            visited.add(pointer); jumps += 1
            if jumps > 32: raise ValueError("Too many compression pointer jumps")
            if end_offset is None: end_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("Reserved DNS label encoding")
        cursor += 1
        if length == 0:
            if end_offset is None: end_offset = cursor
            break
        if length > 63 or cursor + length > len(packet):
            raise ValueError("Invalid DNS label length")
        labels.append(packet[cursor:cursor+length].decode("idna"))
        cursor += length
        if sum(len(x.encode("idna")) + 1 for x in labels) + 1 > 255:
            raise ValueError("Decoded DNS name exceeds 255 octets")
    return ".".join(labels) + ("." if labels else "."), end_offset

def build_query(name: str, qtype: str = "A", ident: Optional[int] = None,
                recursion_desired: bool = True) -> bytes:
    qtype = qtype.upper()
    if qtype not in TYPE_TO_CODE: raise ValueError(f"Unsupported query type: {qtype}")
    ident = random.randrange(0, 65536) if ident is None else ident
    flags = 0x0100 if recursion_desired else 0
    return (HEADER.pack(ident, flags, 1, 0, 0, 0) +
            encode_name(name) + QUESTION_TAIL.pack(TYPE_TO_CODE[qtype], CLASS_IN))

def _encode_record(rr: DNSRecord, out: bytearray, name_offsets: dict):
    owner = rr.name.rstrip(".").lower()
    if owner in name_offsets:
        out.extend(struct.pack("!H", 0xC000 | name_offsets[owner]))
    else:
        name_offsets[owner] = len(out)
        out.extend(encode_name(rr.name))
    typ = TYPE_TO_CODE[rr.rtype.upper()]
    out.extend(struct.pack("!HHI", typ, rr.rclass, rr.ttl))
    length_pos = len(out); out.extend(b"\x00\x00")
    if rr.rtype.upper() in ("NS", "CNAME"):
        target = rr.value.rstrip(".").lower()
        if target in name_offsets:
            rdata = struct.pack("!H", 0xC000 | name_offsets[target])
        else:
            name_offsets[target] = len(out)
            rdata = encode_name(rr.value)
    elif rr.rtype.upper() == "MX":
        pref, exchange = rr.value.split(None, 1)
        target = exchange.rstrip(".").lower()
        if target in name_offsets:
            rdata = struct.pack("!H", int(pref)) + struct.pack("!H", 0xC000 | name_offsets[target])
        else:
            name_offsets[target] = len(out) + 2
            rdata = struct.pack("!H", int(pref)) + encode_name(exchange)
    else:
        rdata = encode_rdata(rr.rtype, rr.value)
    out.extend(rdata)
    struct.pack_into("!H", out, length_pos, len(rdata))

def encode_message(msg: DNSMessage) -> bytes:
    out = bytearray(HEADER.pack(msg.ident, msg.flags, len(msg.questions),
                                len(msg.answers), len(msg.authorities), len(msg.additionals)))
    name_offsets = {}
    for q in msg.questions:
        out.extend(encode_name(q.name))
        out.extend(QUESTION_TAIL.pack(TYPE_TO_CODE.get(q.qtype.upper(), TYPE_ANY), q.qclass))
    for section in (msg.answers, msg.authorities, msg.additionals):
        for rr in section: _encode_record(rr, out, name_offsets)
    return bytes(out)

def parse_message(packet: bytes) -> DNSMessage:
    if len(packet) < 12: raise ValueError("DNS packet shorter than 12-byte header")
    ident, flags, qd, an, ns, ar = HEADER.unpack_from(packet, 0)
    msg = DNSMessage(ident, flags)
    offset = 12
    for _ in range(qd):
        name, offset = decode_name(packet, offset)
        if offset + 4 > len(packet): raise ValueError("Truncated DNS question")
        typ, cls = QUESTION_TAIL.unpack_from(packet, offset); offset += 4
        msg.questions.append(DNSQuestion(name, CODE_TO_TYPE.get(typ, f"TYPE{typ}"), cls))
    for target_list, count in ((msg.answers, an), (msg.authorities, ns), (msg.additionals, ar)):
        for _ in range(count):
            name, offset = decode_name(packet, offset)
            if offset + 10 > len(packet): raise ValueError("Truncated resource-record header")
            typ, cls, ttl, rdlen = RR_TAIL.unpack_from(packet, offset); offset += 10
            if offset + rdlen > len(packet): raise ValueError("RDATA extends beyond packet")
            raw = packet[offset:offset+rdlen]
            rtype = CODE_TO_TYPE.get(typ, f"TYPE{typ}")
            value = decode_rdata(rtype, raw, packet, offset)
            target_list.append(DNSRecord(name, rtype, value, ttl, cls))
            offset += rdlen
    return msg
