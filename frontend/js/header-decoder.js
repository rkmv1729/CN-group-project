/**
 * Group 3 — Protocol Visualizer (Roll 27)
 * Module: Bit-Level Header Decoder & Wireshark Hex Inspector (frontend/js/header-decoder.js)
 *
 * Provides interactive bit-level RFC header breakdown (RFC 951 BOOTP 300-byte layout,
 * RFC 1035 DNS 12-byte header + Question/Answer RRs, RFC 854 Telnet IAC sequences)
 * synchronized side-by-side with a byte-accurate hex + ASCII dump.
 */

(function () {
  'use strict';

  class HeaderDecoder {
    constructor() {
      this.currentPacket = null;
      this.currentFields = [];
      this.currentBytes = [];
      this.activeFieldIndex = null;
    }

    init() {
      const sampleBootpBtn = document.getElementById('decoder-load-bootp-sample');
      if (sampleBootpBtn) {
        sampleBootpBtn.addEventListener('click', () => {
          if (window.VisualizerApp) {
            const sample = window.VisualizerApp.createSyntheticBootpPair()[1];
            this.inspectPacket(sample, false);
          }
        });
      }

      const sampleDnsBtn = document.getElementById('decoder-load-dns-sample');
      if (sampleDnsBtn) {
        sampleDnsBtn.addEventListener('click', () => {
          if (window.VisualizerApp) {
            const sample = window.VisualizerApp.createSyntheticDnsPair('example.local', 'A')[1];
            this.inspectPacket(sample, false);
          }
        });
      }

      const sampleTelnetBtn = document.getElementById('decoder-load-telnet-sample');
      if (sampleTelnetBtn) {
        sampleTelnetBtn.addEventListener('click', () => {
          if (window.VisualizerApp) {
            const sample = window.VisualizerApp.createSyntheticTelnetPacket();
            this.inspectPacket(sample, false);
          }
        });
      }
    }

    /**
     * Load a packet into the Header Decoder and optionally switch to the Decoder tab.
     */
    inspectPacket(pkt, switchTab = true) {
      if (!pkt) return;
      this.currentPacket = pkt;
      this.activeFieldIndex = 0;

      if (switchTab && window.VisualizerApp) {
        window.VisualizerApp.switchTab('decoder');
      }

      this.currentBytes = this.extractBytes(pkt);
      this.currentFields = this.buildFieldSchema(pkt, this.currentBytes);
      this.render();
    }

    /**
     * Parse raw_hex (Wireshark dump format, space-separated hex, or plain hex)
     * into an array of numeric byte values [0..255]. If raw_hex is empty,
     * synthesize accurate wire bytes from the decoded packet structure.
     */
    extractBytes(pkt) {
      const raw = String(pkt.raw_hex || '').trim();
      if (raw) {
        const lines = raw.split(/\r?\n/);
        const bytes = [];
        for (const line of lines) {
          // Match Wireshark format: "0000  01 01 06 00 ...  ....F."
          const wsMatch = line.match(/^[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s+)+)/);
          if (wsMatch) {
            const hexTokens = wsMatch[1].trim().split(/\s+/);
            for (const tok of hexTokens) {
              if (/^[0-9a-fA-F]{2}$/.test(tok)) {
                bytes.push(parseInt(tok, 16));
              }
            }
            continue;
          }
          // Otherwise check space-separated or contiguous hex
          const cleaned = line.replace(/[^0-9a-fA-F]/g, '');
          if (cleaned.length >= 2 && cleaned.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleaned)) {
            for (let i = 0; i < cleaned.length; i += 2) {
              bytes.push(parseInt(cleaned.slice(i, i + 2), 16));
            }
          }
        }
        if (bytes.length > 0) return bytes;
      }

      // Fallback: synthesize bytes from packet fields
      return this.synthesizeBytesFromPacket(pkt);
    }

    synthesizeBytesFromPacket(pkt) {
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();
      const p = pkt.packet || {};

      if (proto === 'BOOTP') {
        const buf = new Array(300).fill(0);
        buf[0] = Number(p.op || (pkt.type === 'BOOTREPLY' ? 2 : 1));
        buf[1] = Number(p.htype || 1);
        buf[2] = Number(p.hlen || 6);
        buf[3] = Number(p.hops || 0);

        const xidNum = parseInt(String(p.xid || '0x3903f326').replace(/^0x/i, ''), 16) >>> 0;
        buf[4] = (xidNum >>> 24) & 0xff;
        buf[5] = (xidNum >>> 16) & 0xff;
        buf[6] = (xidNum >>> 8) & 0xff;
        buf[7] = xidNum & 0xff;

        const secs = Number(p.secs || 0);
        buf[8] = (secs >>> 8) & 0xff;
        buf[9] = secs & 0xff;

        const flags = parseInt(String(p.flags || '0x8000').replace(/^0x/i, ''), 16) & 0xffff;
        buf[10] = (flags >>> 8) & 0xff;
        buf[11] = flags & 0xff;

        const writeIp = (offset, ipStr) => {
          const parts = String(ipStr || '0.0.0.0').split('.').map((n) => parseInt(n, 10) || 0);
          for (let i = 0; i < 4; i++) buf[offset + i] = parts[i] & 0xff;
        };
        writeIp(12, p.ciaddr);
        writeIp(16, p.yiaddr);
        writeIp(20, p.siaddr);
        writeIp(24, p.giaddr);

        const macParts = String(p.chaddr || 'aa:bb:cc:dd:ee:01')
          .split(':')
          .map((h) => parseInt(h, 16) || 0);
        for (let i = 0; i < Math.min(6, macParts.length); i++) {
          buf[28 + i] = macParts[i] & 0xff;
        }

        const writeAscii = (offset, maxLen, str) => {
          const s = String(str || '');
          for (let i = 0; i < Math.min(maxLen, s.length); i++) {
            buf[offset + i] = s.charCodeAt(i) & 0xff;
          }
        };
        writeAscii(44, 64, p.sname || 'bootp.group3.local');
        writeAscii(108, 128, p.file || '/pxelinux.0');

        // RFC 1048 Magic Cookie 99.130.83.99 (0x63, 0x82, 0x53, 0x63)
        buf[236] = 0x63;
        buf[237] = 0x82;
        buf[238] = 0x53;
        buf[239] = 0x63;
        buf[240] = 0xff; // End option
        return buf;
      }

      if (proto === 'DNS') {
        const bytes = [];
        const idNum = parseInt(String(p.id || '0x1a2b').replace(/^0x/i, ''), 16) & 0xffff;
        const flagsNum =
          parseInt(
            String(p.flags || (pkt.type?.includes('RESPONSE') ? '0x8580' : '0x0100')).replace(/^0x/i, ''),
            16
          ) & 0xffff;
        const qdcount = Number(p.qdcount ?? 1);
        const ancount = Number(p.ancount ?? (Array.isArray(p.answers) ? p.answers.length : 0));
        const nscount = Number(p.nscount ?? 0);
        const arcount = Number(p.arcount ?? 0);

        const push16 = (v) => {
          bytes.push((v >>> 8) & 0xff, v & 0xff);
        };
        push16(idNum);
        push16(flagsNum);
        push16(qdcount);
        push16(ancount);
        push16(nscount);
        push16(arcount);

        // Encode QNAME
        const qname = String(p.qname || p.domain || 'example.local').replace(/\.$/, '');
        for (const label of qname.split('.')) {
          bytes.push(label.length & 0xff);
          for (let i = 0; i < label.length; i++) bytes.push(label.charCodeAt(i) & 0xff);
        }
        bytes.push(0x00);

        const qtypeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, AAAA: 28 };
        const qtype = Number(p.qtype_code || qtypeMap[p.qtype || p.record_type || 'A'] || 1);
        push16(qtype);
        push16(1); // QCLASS IN = 1

        // If response has answers, encode first answer with pointer 0xc00c
        if (ancount > 0) {
          push16(0xc00c); // Name pointer to offset 12
          push16(qtype);
          push16(1); // CLASS IN
          bytes.push(0x00, 0x00, 0x0e, 0x10); // TTL = 3600s
          const rdataStr = p.answers?.[0]?.rdata || p.rdata || '192.168.1.10';
          if (qtype === 1 && /^\d+\.\d+\.\d+\.\d+$/.test(rdataStr)) {
            push16(4);
            rdataStr.split('.').forEach((oct) => bytes.push(parseInt(oct, 10) & 0xff));
          } else {
            push16(rdataStr.length);
            for (let i = 0; i < rdataStr.length; i++) bytes.push(rdataStr.charCodeAt(i) & 0xff);
          }
        }
        return bytes;
      }

      // TELNET
      if (Array.isArray(p.raw_bytes) && p.raw_bytes.length > 0) {
        return p.raw_bytes;
      }
      // Default Telnet IAC negotiation + command bytes
      return [0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03, 0xff, 0xfd, 0x1f, 0x77, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x0d, 0x0a];
    }

    /**
     * Build the interactive RFC bit-level field breakdown for the active packet
     */
    buildFieldSchema(pkt, bytes) {
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();
      const p = pkt.packet || {};

      if (proto === 'BOOTP') {
        const opVal = p.op ?? bytes[0] ?? 1;
        const opName = opVal === 1 ? '1 (BOOTREQUEST)' : opVal === 2 ? '2 (BOOTREPLY)' : String(opVal);
        return [
          {
            name: 'op (Message Opcode)',
            shortName: 'op (8b)',
            bitSpan: 8,
            byteStart: 0,
            byteEnd: 0,
            value: opName,
            hex: this.sliceHex(bytes, 0, 1),
            rfc: 'RFC 951 §3 — Packet opcode: 1 = BOOTREQUEST, 2 = BOOTREPLY.',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'htype (Hardware Address Type)',
            shortName: 'htype (8b)',
            bitSpan: 8,
            byteStart: 1,
            byteEnd: 1,
            value: `${p.htype ?? bytes[1] ?? 1} (Ethernet 10Mb)`,
            hex: this.sliceHex(bytes, 1, 2),
            rfc: 'RFC 951 §3 — Hardware address type (1 = 10mb Ethernet per ARP RFC 826).',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'hlen (Hardware Address Length)',
            shortName: 'hlen (8b)',
            bitSpan: 8,
            byteStart: 2,
            byteEnd: 2,
            value: `${p.hlen ?? bytes[2] ?? 6} bytes`,
            hex: this.sliceHex(bytes, 2, 3),
            rfc: 'RFC 951 §3 — Hardware address length in octets (6 for IEEE 802.3 MAC).',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'hops (Gateway Hops)',
            shortName: 'hops (8b)',
            bitSpan: 8,
            byteStart: 3,
            byteEnd: 3,
            value: `${p.hops ?? bytes[3] ?? 0}`,
            hex: this.sliceHex(bytes, 3, 4),
            rfc: 'RFC 951 §3 — Client sets to 0; incremented by relay agents (BOOTP forwarding).',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'xid (Transaction ID)',
            shortName: 'xid (32 bits)',
            bitSpan: 32,
            byteStart: 4,
            byteEnd: 7,
            value: String(p.xid || this.sliceHex(bytes, 4, 8)),
            hex: this.sliceHex(bytes, 4, 8),
            rfc: 'RFC 951 §3 — 32-bit random transaction ID chosen by client; echoed by server to match replies.',
            color: 'border-sky-500/50 bg-sky-950/40',
          },
          {
            name: 'secs (Seconds Elapsed)',
            shortName: 'secs (16 bits)',
            bitSpan: 16,
            byteStart: 8,
            byteEnd: 9,
            value: `${p.secs ?? 0}s`,
            hex: this.sliceHex(bytes, 8, 10),
            rfc: 'RFC 951 §3 — Seconds elapsed since client began boot request process.',
            color: 'border-indigo-500/50 bg-indigo-950/40',
          },
          {
            name: 'flags (Bootp Broadcast Flags)',
            shortName: 'flags (16 bits)',
            bitSpan: 16,
            byteStart: 10,
            byteEnd: 11,
            value: `${p.flags || '0x8000'} (B=1 Broadcast)`,
            hex: this.sliceHex(bytes, 10, 12),
            rfc: 'RFC 1542 / RFC 951 — MSB bit 0 is Broadcast flag (0x8000 = broadcast reply requested).',
            color: 'border-indigo-500/50 bg-indigo-950/40',
          },
          {
            name: 'ciaddr (Client IP Address)',
            shortName: 'ciaddr (32 bits)',
            bitSpan: 32,
            byteStart: 12,
            byteEnd: 15,
            value: p.ciaddr || '0.0.0.0',
            hex: this.sliceHex(bytes, 12, 16),
            rfc: 'RFC 951 §3 — Client IP address; filled in by client only if known.',
            color: 'border-slate-500/50 bg-slate-900/60',
          },
          {
            name: 'yiaddr ("Your" Assigned Client IP)',
            shortName: 'yiaddr (32 bits)',
            bitSpan: 32,
            byteStart: 16,
            byteEnd: 19,
            value: p.yiaddr || '0.0.0.0',
            hex: this.sliceHex(bytes, 16, 20),
            rfc: 'RFC 951 §3 — "Your" IP address assigned by the BOOTP server from static map or pool.',
            color: 'border-emerald-500/60 bg-emerald-950/40',
          },
          {
            name: 'siaddr (Server IP Address)',
            shortName: 'siaddr (32 bits)',
            bitSpan: 32,
            byteStart: 20,
            byteEnd: 23,
            value: p.siaddr || '0.0.0.0',
            hex: this.sliceHex(bytes, 20, 24),
            rfc: 'RFC 951 §3 — IP address of the BOOTP server returning the BOOTREPLY.',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'giaddr (Gateway / Relay IP Address)',
            shortName: 'giaddr (32 bits)',
            bitSpan: 32,
            byteStart: 24,
            byteEnd: 27,
            value: p.giaddr || '0.0.0.0',
            hex: this.sliceHex(bytes, 24, 28),
            rfc: 'RFC 951 §3 — Gateway IP address used for cross-subnet BOOTP relay.',
            color: 'border-blue-500/50 bg-blue-950/40',
          },
          {
            name: 'chaddr (Client Hardware MAC Address — 16 bytes)',
            shortName: 'chaddr (16 bytes / 128 bits)',
            bitSpan: 32,
            byteStart: 28,
            byteEnd: 43,
            value: p.chaddr || 'aa:bb:cc:dd:ee:01',
            hex: this.sliceHex(bytes, 28, 44),
            rfc: 'RFC 951 §3 — 16-byte client hardware address field (first 6 bytes hold Ethernet MAC).',
            color: 'border-amber-500/50 bg-amber-950/40',
          },
          {
            name: 'sname (Server Host Name — 64 bytes)',
            shortName: 'sname (64 bytes null-terminated)',
            bitSpan: 32,
            byteStart: 44,
            byteEnd: 107,
            value: p.sname || '(empty / null-padded)',
            hex: this.sliceHex(bytes, 44, 60) + ' ...',
            rfc: 'RFC 951 §3 — Optional 64-byte null-terminated server hostname string.',
            color: 'border-slate-500/50 bg-slate-900/60',
          },
          {
            name: 'file (Boot File Name — 128 bytes)',
            shortName: 'file (128 bytes null-terminated)',
            bitSpan: 32,
            byteStart: 108,
            byteEnd: 235,
            value: p.file || '(empty / null-padded)',
            hex: this.sliceHex(bytes, 108, 124) + ' ...',
            rfc: 'RFC 951 §3 — 128-byte boot file path string for diskless network boot (TFTP).',
            color: 'border-slate-500/50 bg-slate-900/60',
          },
          {
            name: 'vend (Vendor-Specific Area & Magic Cookie — 64 bytes)',
            shortName: 'vend (64 bytes · Magic Cookie 99.130.83.99)',
            bitSpan: 32,
            byteStart: 236,
            byteEnd: Math.min(299, Math.max(239, bytes.length - 1)),
            value: p.vend_hex ? `0x${String(p.vend_hex).slice(0, 24)}...` : 'Magic Cookie 0x63825363 (RFC 1048)',
            hex: this.sliceHex(bytes, 236, Math.min(256, bytes.length)),
            rfc: 'RFC 951 / RFC 1048 — 64-byte vendor extensions starting with Magic Cookie 99.130.83.99.',
            color: 'border-purple-500/50 bg-purple-950/40',
          },
        ];
      }

      if (proto === 'DNS') {
        const flagsHex = this.sliceHex(bytes, 2, 4);
        const flagsInt = ((bytes[2] || 0) << 8) | (bytes[3] || 0);
        const qr = (flagsInt >>> 15) & 1;
        const aa = (flagsInt >>> 10) & 1;
        const rd = (flagsInt >>> 8) & 1;
        const ra = (flagsInt >>> 7) & 1;
        const rcode = flagsInt & 0xf;
        const rcodeNames = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

        return [
          {
            name: 'ID (Transaction Identifier)',
            shortName: 'ID (16 bits)',
            bitSpan: 16,
            byteStart: 0,
            byteEnd: 1,
            value: p.id || `0x${this.sliceHex(bytes, 0, 2).replace(/\s+/g, '')}`,
            hex: this.sliceHex(bytes, 0, 2),
            rfc: 'RFC 1035 §4.1.1 — 16-bit identifier assigned by the program that generates any kind of query.',
            color: 'border-emerald-500/50 bg-emerald-950/40',
          },
          {
            name: 'Flags (QR | Opcode | AA | TC | RD | RA | Z | RCODE)',
            shortName: 'Flags (16 bits)',
            bitSpan: 16,
            byteStart: 2,
            byteEnd: 3,
            value: `QR=${qr} AA=${aa} RD=${rd} RA=${ra} RCODE=${rcode} (${rcodeNames[rcode] || 'OK'})`,
            hex: flagsHex,
            rfc: 'RFC 1035 §4.1.1 — 16-bit control flags: QR(1), Opcode(4), AA(1), TC(1), RD(1), RA(1), Z(3), RCODE(4).',
            color: 'border-teal-500/50 bg-teal-950/40',
          },
          {
            name: 'QDCOUNT (Question Count)',
            shortName: 'QDCOUNT (16 bits)',
            bitSpan: 16,
            byteStart: 4,
            byteEnd: 5,
            value: `${p.qdcount ?? (((bytes[4] || 0) << 8) | (bytes[5] || 1))} question(s)`,
            hex: this.sliceHex(bytes, 4, 6),
            rfc: 'RFC 1035 §4.1.1 — Unsigned 16-bit integer specifying the number of entries in the question section.',
            color: 'border-sky-500/50 bg-sky-950/40',
          },
          {
            name: 'ANCOUNT (Answer Record Count)',
            shortName: 'ANCOUNT (16 bits)',
            bitSpan: 16,
            byteStart: 6,
            byteEnd: 7,
            value: `${p.ancount ?? (((bytes[6] || 0) << 8) | (bytes[7] || 0))} answer RR(s)`,
            hex: this.sliceHex(bytes, 6, 8),
            rfc: 'RFC 1035 §4.1.1 — Unsigned 16-bit integer specifying the number of resource records in the answer section.',
            color: 'border-emerald-500/50 bg-emerald-950/40',
          },
          {
            name: 'NSCOUNT (Authority Record Count)',
            shortName: 'NSCOUNT (16 bits)',
            bitSpan: 16,
            byteStart: 8,
            byteEnd: 9,
            value: `${p.nscount ?? (((bytes[8] || 0) << 8) | (bytes[9] || 0))} authority RR(s)`,
            hex: this.sliceHex(bytes, 8, 10),
            rfc: 'RFC 1035 §4.1.1 — Number of name server resource records in the authority records section.',
            color: 'border-slate-500/50 bg-slate-900/60',
          },
          {
            name: 'ARCOUNT (Additional Record Count)',
            shortName: 'ARCOUNT (16 bits)',
            bitSpan: 16,
            byteStart: 10,
            byteEnd: 11,
            value: `${p.arcount ?? (((bytes[10] || 0) << 8) | (bytes[11] || 0))} additional RR(s)`,
            hex: this.sliceHex(bytes, 10, 12),
            rfc: 'RFC 1035 §4.1.1 — Number of resource records in the additional records section.',
            color: 'border-slate-500/50 bg-slate-900/60',
          },
          {
            name: 'Question Section (QNAME + QTYPE + QCLASS)',
            shortName: 'Question Section (Variable)',
            bitSpan: 32,
            byteStart: 12,
            byteEnd: Math.min(bytes.length - 1, 31),
            value: `${p.qname || p.domain || 'example.local'} · QTYPE=${p.qtype || p.record_type || 'A'} · QCLASS=IN`,
            hex: this.sliceHex(bytes, 12, Math.min(bytes.length, 32)),
            rfc: 'RFC 1035 §4.1.2 — Length-prefixed domain labels terminated by 0x00, followed by 16-bit QTYPE and 16-bit QCLASS.',
            color: 'border-cyan-500/50 bg-cyan-950/40',
          },
          ...(bytes.length > 32
            ? [
                {
                  name: 'Resource Records Section (Answer / Authority / Additional)',
                  shortName: 'Answer RRs (Compressed Name Pointer 0xC00C + TYPE + CLASS + TTL + RDLENGTH + RDATA)',
                  bitSpan: 32,
                  byteStart: 32,
                  byteEnd: bytes.length - 1,
                  value:
                    Array.isArray(p.answers) && p.answers.length
                      ? p.answers.map((a) => `${a.type || 'A'}: ${a.rdata || a.address}`).join(' | ')
                      : p.rdata || 'Compressed RR Payload',
                  hex: this.sliceHex(bytes, 32, bytes.length),
                  rfc: 'RFC 1035 §4.1.3 & §4.1.4 — Resource Record with message compression pointer (top 2 bits 11 = 0xC0).',
                  color: 'border-emerald-500/60 bg-emerald-950/40',
                },
              ]
            : []),
        ];
      }

      // TELNET (RFC 854)
      return this.buildTelnetFieldSchema(pkt, bytes);
    }

    buildTelnetFieldSchema(pkt, bytes) {
      const fields = [];
      let i = 0;
      const cmdNames = {
        240: 'SE (Subnegotiation End)',
        241: 'NOP',
        250: 'SB (Subnegotiation Begin)',
        251: 'WILL (Sender wants to enable)',
        252: 'WONT (Sender refuses)',
        253: 'DO (Sender requests receiver enable)',
        254: 'DONT (Sender requests receiver disable)',
        255: 'IAC (Interpret As Command 0xFF)',
      };
      const optNames = {
        1: 'ECHO (RFC 857)',
        3: 'SGA — Suppress Go Ahead (RFC 858)',
        24: 'TTYPE — Terminal Type (RFC 1091)',
        31: 'NAWS — Negotiate About Window Size (RFC 1073)',
        34: 'LINEMODE (RFC 1184)',
      };

      while (i < bytes.length) {
        if (bytes[i] === 0xff && i + 2 < bytes.length && bytes[i + 1] >= 251 && bytes[i + 1] <= 254) {
          const cmd = bytes[i + 1];
          const opt = bytes[i + 2];
          fields.push({
            name: `IAC ${cmdNames[cmd]?.split(' ')[0] || cmd} ${optNames[opt]?.split(' ')[0] || opt}`,
            shortName: `IAC (0xFF) · ${cmdNames[cmd]?.split(' ')[0] || cmd} · Opt ${opt}`,
            bitSpan: 24,
            byteStart: i,
            byteEnd: i + 2,
            value: `0xFF (${cmdNames[255]}) → 0x${cmd.toString(16).toUpperCase()} (${cmdNames[cmd]}) → 0x${opt
              .toString(16)
              .padStart(2, '0')
              .toUpperCase()} (${optNames[opt] || 'Option ' + opt})`,
            hex: this.sliceHex(bytes, i, i + 3),
            rfc: 'RFC 854 §Option Negotiation — 3-byte Telnet IAC command sequence negotiating terminal capabilities.',
            color: 'border-amber-500/60 bg-amber-950/40',
          });
          i += 3;
        } else {
          const start = i;
          while (i < bytes.length && bytes[i] !== 0xff) i++;
          const ascii = bytes
            .slice(start, i)
            .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : b === 13 ? '\\r' : b === 10 ? '\\n' : '.'))
            .join('');
          fields.push({
            name: 'NVT ASCII Data Stream / Shell Payload',
            shortName: `NVT Data (${i - start} bytes)`,
            bitSpan: 32,
            byteStart: start,
            byteEnd: i - 1,
            value: `"${ascii}"`,
            hex: this.sliceHex(bytes, start, i),
            rfc: 'RFC 854 §Network Virtual Terminal (NVT) — 7-bit US-ASCII stream terminated by CR LF (0x0D 0x0A).',
            color: 'border-orange-500/50 bg-orange-950/40',
          });
        }
      }
      return fields;
    }

    sliceHex(bytes, start, end) {
      return bytes
        .slice(start, end)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');
    }

    render() {
      const bitContainer = document.getElementById('decoder-bit-grid');
      const hexContainer = document.getElementById('decoder-hex-dump');
      const detailBox = document.getElementById('decoder-field-inspector');
      const headerSummary = document.getElementById('decoder-packet-meta');
      if (!bitContainer || !hexContainer) return;

      if (!this.currentPacket) {
        return;
      }

      const pkt = this.currentPacket;
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();

      if (headerSummary) {
        headerSummary.innerHTML = `
          <span class="px-2.5 py-0.5 rounded text-xs font-bold bg-sky-500/20 text-sky-300 border border-sky-500/40">${proto}</span>
          <span class="text-sm font-semibold text-white">${pkt.type || ''}</span>
          <span class="text-xs font-mono text-slate-400">${pkt.source?.ip || '127.0.0.1'}:${pkt.source?.port ?? '—'} → ${
          pkt.destination?.ip || '127.0.0.1'
        }:${pkt.destination?.port ?? '—'}</span>
          <span class="text-xs font-mono text-slate-400 ml-auto">${this.currentBytes.length} bytes on wire</span>
        `;
      }

      // Render 32-bit ruler header
      let rulerCells = '';
      for (let b = 0; b < 32; b++) {
        rulerCells += `<div class="text-[10px] text-center py-1 text-slate-400 bg-slate-900/90 font-mono">${b}</div>`;
      }

      // Group fields into 32-bit rows
      let rowsHtml = '<div class="bit-grid-row">';
      let currentRowBits = 0;

      this.currentFields.forEach((f, idx) => {
        const span = Math.min(32, Math.max(8, f.bitSpan || 32));
        if (currentRowBits + span > 32) {
          rowsHtml += '</div><div class="bit-grid-row">';
          currentRowBits = 0;
        }
        const activeClass = this.activeFieldIndex === idx ? 'active-field' : '';
        rowsHtml += `
          <div class="bit-field-cell ${f.color} ${activeClass}"
               style="grid-column: span ${span} / span ${span};"
               data-field-idx="${idx}">
            <div class="flex items-center justify-between gap-1 text-[10px] text-slate-400 font-mono">
              <span>${f.shortName}</span>
              <span>B[${f.byteStart}${f.byteEnd > f.byteStart ? '..' + f.byteEnd : ''}]</span>
            </div>
            <div class="text-xs font-bold text-white font-mono truncate mt-0.5">${f.value}</div>
          </div>
        `;
        currentRowBits += span;
        if (currentRowBits >= 32) {
          rowsHtml += '</div><div class="bit-grid-row">';
          currentRowBits = 0;
        }
      });
      rowsHtml += '</div>';

      bitContainer.innerHTML = `
        <div class="bit-grid-header mb-1">${rulerCells}</div>
        ${rowsHtml}
      `;

      // Render Wireshark-style Hex + ASCII dump (16 bytes per row)
      const activeField =
        this.activeFieldIndex !== null ? this.currentFields[this.activeFieldIndex] : null;
      const hlStart = activeField ? activeField.byteStart : -1;
      const hlEnd = activeField ? activeField.byteEnd : -1;

      let hexRowsHtml = '';
      for (let offset = 0; offset < this.currentBytes.length; offset += 16) {
        const rowBytes = this.currentBytes.slice(offset, offset + 16);
        const offsetHex = offset.toString(16).padStart(4, '0').toUpperCase();

        let hexCells = '';
        let asciiCells = '';

        for (let i = 0; i < 16; i++) {
          const byteIndex = offset + i;
          if (i === 8) {
            hexCells += `<span class="inline-block w-2"></span>`;
          }
          if (i < rowBytes.length) {
            const b = rowBytes[i];
            const isHl = byteIndex >= hlStart && byteIndex <= hlEnd;
            const hexStr = b.toString(16).padStart(2, '0').toUpperCase();
            const ch = b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
            const safeCh = ch.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

            hexCells += `<span class="hex-byte ${
              isHl ? 'highlighted' : 'text-slate-300'
            }" data-byte-idx="${byteIndex}">${hexStr}</span>`;
            asciiCells += `<span class="ascii-char ${
              isHl ? 'highlighted' : 'text-slate-400'
            }" data-byte-idx="${byteIndex}">${safeCh}</span>`;
          } else {
            hexCells += `<span class="hex-byte text-transparent select-none">00</span>`;
            asciiCells += `<span class="ascii-char text-transparent select-none">.</span>`;
          }
        }

        hexRowsHtml += `
          <div class="flex items-center gap-3 py-0.5 px-2 rounded hover:bg-slate-800/50">
            <span class="text-xs font-mono text-sky-400/80 select-none w-11">${offsetHex}</span>
            <div class="flex items-center flex-wrap">${hexCells}</div>
            <div class="border-l border-slate-700/80 pl-3 font-mono tracking-tight">${asciiCells}</div>
          </div>
        `;
      }

      hexContainer.innerHTML = hexRowsHtml;

      // Update active field detail card
      this.renderFieldDetail(activeField, detailBox);

      // Attach hover & click listeners on bit cells
      bitContainer.querySelectorAll('.bit-field-cell').forEach((cell) => {
        const idx = Number(cell.getAttribute('data-field-idx'));
        cell.addEventListener('mouseenter', () => {
          this.activeFieldIndex = idx;
          this.updateHighlightsOnly();
        });
        cell.addEventListener('click', () => {
          this.activeFieldIndex = idx;
          this.updateHighlightsOnly();
        });
      });

      // Attach hover & click listeners on hex bytes -> highlight corresponding field
      hexContainer.querySelectorAll('.hex-byte[data-byte-idx]').forEach((byteEl) => {
        const byteIdx = Number(byteEl.getAttribute('data-byte-idx'));
        byteEl.addEventListener('mouseenter', () => {
          const foundIdx = this.currentFields.findIndex(
            (f) => byteIdx >= f.byteStart && byteIdx <= f.byteEnd
          );
          if (foundIdx !== -1 && foundIdx !== this.activeFieldIndex) {
            this.activeFieldIndex = foundIdx;
            this.updateHighlightsOnly();
          }
        });
      });
    }

    updateHighlightsOnly() {
      const bitContainer = document.getElementById('decoder-bit-grid');
      const hexContainer = document.getElementById('decoder-hex-dump');
      const detailBox = document.getElementById('decoder-field-inspector');
      if (!bitContainer || !hexContainer) return;

      const activeField =
        this.activeFieldIndex !== null ? this.currentFields[this.activeFieldIndex] : null;
      const hlStart = activeField ? activeField.byteStart : -1;
      const hlEnd = activeField ? activeField.byteEnd : -1;

      bitContainer.querySelectorAll('.bit-field-cell').forEach((cell) => {
        const idx = Number(cell.getAttribute('data-field-idx'));
        cell.classList.toggle('active-field', idx === this.activeFieldIndex);
      });

      hexContainer.querySelectorAll('[data-byte-idx]').forEach((el) => {
        const bIdx = Number(el.getAttribute('data-byte-idx'));
        const isHl = bIdx >= hlStart && bIdx <= hlEnd;
        el.classList.toggle('highlighted', isHl);
      });

      this.renderFieldDetail(activeField, detailBox);
    }

    renderFieldDetail(field, detailBox) {
      if (!detailBox) return;
      if (!field) {
        detailBox.innerHTML = `<p class="text-xs text-slate-400">Hover or click any header field or hex byte to inspect its RFC specification and binary encoding.</p>`;
        return;
      }

      const byteCount = field.byteEnd - field.byteStart + 1;
      detailBox.innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <span class="text-xs font-mono uppercase tracking-wider text-sky-400">Active Header Field</span>
            <h4 class="text-base font-bold text-white">${field.name}</h4>
          </div>
          <div class="flex items-center gap-2 text-xs font-mono">
            <span class="px-2 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700">
              Bytes ${field.byteStart}–${field.byteEnd} (${byteCount} B / ${byteCount * 8} bits)
            </span>
          </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
          <div class="bg-slate-950/70 border border-slate-800 rounded-lg p-2.5">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Decoded Value</div>
            <div class="text-sm font-mono font-bold text-emerald-400 mt-0.5 break-all">${field.value}</div>
          </div>
          <div class="bg-slate-950/70 border border-slate-800 rounded-lg p-2.5">
            <div class="text-[11px] text-slate-400 uppercase font-semibold">Wire Hex Bytes</div>
            <div class="text-sm font-mono text-sky-300 mt-0.5 break-all">${field.hex || '00'}</div>
          </div>
        </div>
        <p class="text-xs text-slate-300 mt-2.5 leading-relaxed">
          <span class="font-semibold text-sky-400">RFC Specification:</span> ${field.rfc}
        </p>
      `;
    }
  }

  window.HeaderDecoder = new HeaderDecoder();
})();
