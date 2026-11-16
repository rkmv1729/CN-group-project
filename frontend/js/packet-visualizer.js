/**
 * Group 3 — Protocol Visualizer (Roll 27)
 * Module: Packet Flow Visualizer (frontend/js/packet-visualizer.js)
 *
 * Renders an interactive, real-time SVG ladder/sequence diagram showing
 * Client <-> Server message exchanges across BOOTP (UDP 10067/10068),
 * DNS (UDP 10053), and TELNET (TCP 2323). Clicking any packet arrow or card
 * drills directly into the Bit-Level Header Decoder.
 */

(function () {
  'use strict';

  const PROTOCOL_META = {
    BOOTP: {
      color: '#3b82f6',
      stroke: '#60a5fa',
      bg: 'rgba(59, 130, 246, 0.16)',
      badgeBg: '#1d4ed8',
      clientLabel: 'BOOTP Client (:10068)',
      serverLabel: 'BOOTP Server (:10067)',
      layer: 'Network Layer (RFC 951)',
    },
    DNS: {
      color: '#10b981',
      stroke: '#34d399',
      bg: 'rgba(16, 185, 129, 0.16)',
      badgeBg: '#047857',
      clientLabel: 'DNS Resolver',
      serverLabel: 'DNS Server (:10053)',
      layer: 'Transport / App (RFC 1035)',
    },
    TELNET: {
      color: '#f59e0b',
      stroke: '#fbbf24',
      bg: 'rgba(245, 158, 11, 0.16)',
      badgeBg: '#b45309',
      clientLabel: 'Telnet Client (xterm.js)',
      serverLabel: 'Telnet Server (:2323)',
      layer: 'Application Layer (RFC 854)',
    },
  };

  class PacketVisualizer {
    constructor() {
      this.filterProtocol = 'ALL';
      this.selectedPacketId = null;
      this.animateFlows = true;
    }

    init() {
      const filterSelect = document.getElementById('seq-protocol-filter');
      if (filterSelect) {
        filterSelect.addEventListener('change', (e) => {
          this.filterProtocol = e.target.value;
          this.render();
        });
      }

      const animToggle = document.getElementById('seq-anim-toggle');
      if (animToggle) {
        animToggle.addEventListener('change', (e) => {
          this.animateFlows = e.target.checked;
          this.render();
        });
      }

      const clearBtn = document.getElementById('seq-clear-btn');
      if (clearBtn) {
        clearBtn.addEventListener('click', () => {
          if (window.VisualizerApp) {
            window.VisualizerApp.clearPackets();
          }
        });
      }
    }

    /**
     * Determine direction ('c2s' = Client -> Server, 's2c' = Server -> Client)
     */
    getDirection(pkt) {
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();
      const type = (pkt.type || '').toUpperCase();
      const dstPort = Number(pkt.destination?.port || 0);
      const srcPort = Number(pkt.source?.port || 0);

      if (proto === 'BOOTP') {
        if (type.includes('REPLY') || srcPort === 10067 || srcPort === 67) return 's2c';
        return 'c2s';
      }
      if (proto === 'DNS') {
        if (
          type.includes('RESPONSE') ||
          type.includes('REPLY') ||
          type.includes('ANSWER') ||
          pkt.packet?.qr === 1 ||
          srcPort === 10053 ||
          srcPort === 53
        ) {
          return 's2c';
        }
        return 'c2s';
      }
      if (proto === 'TELNET') {
        if (
          type.includes('SERVER') ||
          type.includes('WILL') ||
          type.includes('DO') ||
          type.includes('OUTPUT') ||
          srcPort === 2323 ||
          srcPort === 23
        ) {
          if (dstPort === 2323 || dstPort === 23) return 'c2s';
          return 's2c';
        }
        return 'c2s';
      }
      return 'c2s';
    }

    /**
     * Summarize key fields of a packet for the sequence diagram label
     */
    getSummarySubtitle(pkt) {
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();
      const p = pkt.packet || {};
      if (proto === 'BOOTP') {
        const xid = p.xid || '0x00000000';
        const chaddr = p.chaddr || '00:00:00:00:00:00';
        const yiaddr = p.yiaddr && p.yiaddr !== '0.0.0.0' ? ` → yiaddr=${p.yiaddr}` : '';
        return `xid=${xid} · MAC=${chaddr}${yiaddr}`;
      }
      if (proto === 'DNS') {
        const qname = p.qname || p.domain || 'example.local';
        const qtype = p.qtype_name || p.qtype || p.record_type || 'A';
        const ans =
          Array.isArray(p.answers) && p.answers.length > 0
            ? ` → ${p.answers.map((a) => a.rdata || a.data || a.address || '').join(', ')}`
            : p.rdata
            ? ` → ${p.rdata}`
            : '';
        return `id=${p.id || '0x1a2b'} · ${qname} (${qtype})${ans}`;
      }
      if (proto === 'TELNET') {
        if (p.iac_summary) return p.iac_summary;
        if (p.command) return `CMD: ${p.command}`;
        if (p.payload) return `Data: ${String(p.payload).slice(0, 42)}`;
        return `${pkt.source?.ip || '127.0.0.1'}:${pkt.source?.port || '—'} → ${
          pkt.destination?.ip || '127.0.0.1'
        }:${pkt.destination?.port || 2323}`;
      }
      return `${pkt.source?.ip || '127.0.0.1'} → ${pkt.destination?.ip || '127.0.0.1'}`;
    }

    render() {
      const container = document.getElementById('sequence-diagram-canvas');
      const countBadge = document.getElementById('seq-packet-count');
      if (!container || !window.VisualizerApp) return;

      const allPackets = window.VisualizerApp.state.packets || [];
      const filtered = allPackets
        .filter((p) => {
          if (this.filterProtocol === 'ALL') return true;
          return (p.protocol || '').toUpperCase() === this.filterProtocol;
        })
        .slice()
        .reverse(); // chronological order (oldest top -> newest bottom)

      if (countBadge) {
        countBadge.textContent = `${filtered.length} packet${filtered.length === 1 ? '' : 's'}`;
      }

      if (filtered.length === 0) {
        container.innerHTML = `
          <div class="flex flex-col items-center justify-center py-16 text-slate-400">
            <svg class="w-12 h-12 mb-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
                d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
            </svg>
            <p class="text-sm font-medium text-slate-300">No packets captured for this filter yet</p>
            <p class="text-xs text-slate-500 mt-1">Trigger a BOOTP request, DNS query, or Telnet session — or click "Load Demo Exchange" to populate.</p>
          </div>
        `;
        return;
      }

      const width = 900;
      const rowHeight = 76;
      const topOffset = 88;
      const height = Math.max(380, topOffset + filtered.length * rowHeight + 48);

      // 4 Vertical Lifelines:
      // 1. Client Host (x = 150)
      // 2. BOOTP Server :10067 (x = 410)
      // 3. DNS Server :10053 (x = 620)
      // 4. Telnet Server :2323 (x = 800)
      const lifelines = [
        { key: 'CLIENT', x: 145, title: 'Client Node', sub: 'UDP :10068 / Resolver / PTY', color: '#38bdf8' },
        { key: 'BOOTP', x: 405, title: 'BOOTP Server', sub: 'UDP :10067 (RFC 951)', color: '#3b82f6' },
        { key: 'DNS', x: 615, title: 'DNS Server', sub: 'UDP :10053 (RFC 1035)', color: '#10b981' },
        { key: 'TELNET', x: 795, title: 'Telnet Server', sub: 'TCP :2323 (RFC 854)', color: '#f59e0b' },
      ];

      const serverXMap = {
        BOOTP: 405,
        DNS: 615,
        TELNET: 795,
      };

      const firstTs = filtered[0]?._epochMs || Date.now();

      let svgRows = '';
      filtered.forEach((pkt, idx) => {
        const proto = (pkt.protocol || 'BOOTP').toUpperCase();
        const meta = PROTOCOL_META[proto] || PROTOCOL_META.BOOTP;
        const dir = this.getDirection(pkt);
        const y = topOffset + idx * rowHeight;
        const clientX = 145;
        const targetServerX = serverXMap[proto] || 405;

        const x1 = dir === 'c2s' ? clientX : targetServerX;
        const x2 = dir === 'c2s' ? targetServerX : clientX;
        const midX = (x1 + x2) / 2;
        const isSelected = this.selectedPacketId === pkt._uid;

        const deltaMs = Math.max(0, (pkt._epochMs || firstTs) - firstTs);
        const deltaStr = `+${(deltaMs / 1000).toFixed(3)}s`;
        const subtitle = this.escapeXml(this.getSummarySubtitle(pkt));
        const pktType = this.escapeXml(pkt.type || proto);
        const srcEndpoint = `${pkt.source?.ip || '127.0.0.1'}:${pkt.source?.port ?? '—'}`;
        const dstEndpoint = `${pkt.destination?.ip || '127.0.0.1'}:${pkt.destination?.port ?? '—'}`;

        const markerId =
          proto === 'BOOTP' ? 'arrow-bootp' : proto === 'DNS' ? 'arrow-dns' : 'arrow-telnet';

        svgRows += `
          <g class="seq-packet-row" data-pkt-uid="${pkt._uid}">
            <!-- Row hover highlight box -->
            <rect x="16" y="${y - 28}" width="${width - 32}" height="62" rx="8"
              fill="${isSelected ? meta.bg : 'transparent'}"
              stroke="${isSelected ? meta.stroke : 'transparent'}"
              stroke-width="1.5" />

            <!-- Sequence index & relative timestamp on left margin -->
            <text x="28" y="${y - 4}" fill="#94a3b8" font-size="11" font-family="monospace" font-weight="600">#${idx + 1}</text>
            <text x="28" y="${y + 13}" fill="#64748b" font-size="10" font-family="monospace">${deltaStr}</text>

            <!-- Endpoint nodes on lifelines -->
            <circle cx="${x1}" cy="${y + 4}" r="5" fill="${meta.color}" />
            <circle cx="${x2}" cy="${y + 4}" r="5" fill="${meta.color}" />

            <!-- Solid base line + optional animated flow overlay -->
            <line x1="${x1}" y1="${y + 4}" x2="${x2}" y2="${y + 4}"
              stroke="${meta.color}" stroke-width="2.2" stroke-opacity="0.45"
              marker-end="url(#${markerId})" />
            ${
              this.animateFlows
                ? `<line x1="${x1}" y1="${y + 4}" x2="${x2}" y2="${y + 4}"
                    stroke="${meta.stroke}" stroke-width="2.2" class="seq-arrow-animated"
                    marker-end="url(#${markerId})" />`
                : ''
            }

            <!-- Protocol & Message Type Pill above arrow -->
            <rect x="${midX - 135}" y="${y - 22}" width="270" height="20" rx="5"
              fill="#0f172a" stroke="${meta.color}" stroke-width="1" />
            <text x="${midX}" y="${y - 9}" text-anchor="middle" fill="${meta.stroke}"
              font-size="11" font-weight="700" font-family="monospace">
              [${proto}] ${pktType} (${srcEndpoint} → ${dstEndpoint})
            </text>

            <!-- Summary payload details below arrow -->
            <text x="${midX}" y="${y + 21}" text-anchor="middle" fill="#cbd5e1"
              font-size="11" font-family="monospace">
              ${subtitle}
            </text>
          </g>
        `;
      });

      const lifelineSvg = lifelines
        .map(
          (ll) => `
          <g>
            <line x1="${ll.x}" y1="62" x2="${ll.x}" y2="${height - 20}"
              stroke="${ll.color}" stroke-opacity="0.3" stroke-width="1.75" stroke-dasharray="4 4" />
            <rect x="${ll.x - 78}" y="12" width="156" height="44" rx="8"
              fill="#0f172a" stroke="${ll.color}" stroke-width="1.5" />
            <text x="${ll.x}" y="31" text-anchor="middle" fill="#f8fafc" font-size="12" font-weight="700">
              ${ll.title}
            </text>
            <text x="${ll.x}" y="46" text-anchor="middle" fill="#94a3b8" font-size="9.5" font-family="monospace">
              ${ll.sub}
            </text>
          </g>
        `
        )
        .join('');

      container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" class="w-full h-auto min-w-[760px] select-none">
          <defs>
            <marker id="arrow-bootp" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#60a5fa" />
            </marker>
            <marker id="arrow-dns" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
            </marker>
            <marker id="arrow-telnet" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#fbbf24" />
            </marker>
          </defs>
          ${lifelineSvg}
          ${svgRows}
        </svg>
      `;

      // Attach click handlers to inspect any packet in Header Decoder
      container.querySelectorAll('.seq-packet-row').forEach((rowEl) => {
        rowEl.addEventListener('click', () => {
          const uid = rowEl.getAttribute('data-pkt-uid');
          this.selectedPacketId = uid;
          const pkt = window.VisualizerApp.getPacketByUid(uid);
          if (pkt) {
            this.renderQuickInspectBanner(pkt);
            if (window.HeaderDecoder) {
              window.HeaderDecoder.inspectPacket(pkt, false);
            }
          }
          this.render();
        });
      });
    }

    renderQuickInspectBanner(pkt) {
      const panel = document.getElementById('seq-selected-summary');
      if (!panel) return;
      const proto = (pkt.protocol || 'BOOTP').toUpperCase();
      panel.classList.remove('hidden');
      panel.innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-3 bg-slate-900/90 border border-sky-500/40 rounded-lg px-4 py-3">
          <div>
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 text-xs font-bold rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">${proto}</span>
              <span class="text-sm font-semibold text-white">${this.escapeXml(pkt.type || '')}</span>
              <span class="text-xs font-mono text-slate-400">${pkt.source?.ip || '127.0.0.1'}:${pkt.source?.port ?? '—'} → ${pkt.destination?.ip || '127.0.0.1'}:${pkt.destination?.port ?? '—'}</span>
            </div>
            <p class="text-xs font-mono text-slate-300 mt-1">${this.escapeXml(this.getSummarySubtitle(pkt))}</p>
          </div>
          <button id="seq-open-decoder-btn" class="px-3 py-1.5 text-xs font-semibold rounded-md bg-sky-600 hover:bg-sky-500 text-white transition">
            Open in Bit-Level Header Decoder →
          </button>
        </div>
      `;
      const btn = document.getElementById('seq-open-decoder-btn');
      if (btn) {
        btn.addEventListener('click', () => {
          if (window.HeaderDecoder) {
            window.HeaderDecoder.inspectPacket(pkt, true);
          }
        });
      }
    }

    escapeXml(str) {
      return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
  }

  window.PacketVisualizer = new PacketVisualizer();
})();
