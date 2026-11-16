/**
 * Group 3 — Protocol Visualizer (Roll 27)
 * Main Application Controller & WebSocket Event Hub (frontend/js/app.js)
 *
 * Orchestrates:
 *  - Live WebSocket connection to ws://<host>/ws/packets
 *  - REST status & historical log hydration (/api/status, /api/bootp/logs, etc.)
 *  - Unified packet normalization across live WS events and SQLite log rows
 *  - Dashboard protocol control cards, live packet stream table, protocol metrics
 *  - Binary PCAP (.pcap) & JSON packet capture export + Dark/Light theme toggle
 */

(function () {
  'use strict';

  class VisualizerApp {
    constructor() {
      this.state = {
        activeTab: 'dashboard',
        wsConnected: false,
        wsClientCount: 1,
        protocols: {
          bootp: 'stopped',
          dns: 'stopped',
          telnet: 'stopped',
        },
        packets: [],
        logFilter: 'ALL',
        logSearch: '',
      };
      this.ws = null;
      this.uidCounter = 1;
      this.reconnectTimer = null;
    }

    async init() {
      this.bindNavigation();
      this.bindDashboardControls();
      this.connectPacketWebSocket();

      // Initialize sub-modules
      window.PacketVisualizer?.init();
      window.HeaderDecoder?.init();
      await window.BootpSimulator?.init();
      await window.DnsTool?.init();
      window.TelnetTerminal?.init();

      // Hydrate status and historical logs from backend if running
      await this.fetchSystemStatus();
      await this.fetchHistoricalLogs();

      // If no packets exist yet in DB, seed an initial RFC-accurate set so the
      // Sequence Diagram, Header Decoder, and Dashboard are immediately inspectable.
      if (this.state.packets.length === 0) {
        this.loadDemoExchange(true);
      } else {
        this.refreshAllViews();
        if (window.HeaderDecoder && this.state.packets[0]) {
          window.HeaderDecoder.inspectPacket(this.state.packets[0], false);
        }
      }

      // Poll /api/status every 6 seconds
      setInterval(() => this.fetchSystemStatus(), 6000);
    }

    bindNavigation() {
      document.querySelectorAll('[data-nav-tab]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const tab = btn.getAttribute('data-nav-tab');
          if (tab) this.switchTab(tab);
        });
      });

      const themeBtn = document.getElementById('theme-toggle-btn');
      if (themeBtn) {
        themeBtn.addEventListener('click', () => {
          document.documentElement.classList.toggle('light-theme');
          const isLight = document.documentElement.classList.contains('light-theme');
          themeBtn.textContent = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
        });
      }
    }

    switchTab(tabName) {
      this.state.activeTab = tabName;
      document.querySelectorAll('[data-nav-tab]').forEach((btn) => {
        const isMatch = btn.getAttribute('data-nav-tab') === tabName;
        btn.classList.toggle('active', isMatch);
      });

      document.querySelectorAll('[data-tab-panel]').forEach((panel) => {
        const isMatch = panel.getAttribute('data-tab-panel') === tabName;
        panel.classList.toggle('hidden', !isMatch);
      });

      if (tabName === 'visualizer') {
        window.PacketVisualizer?.render();
      } else if (tabName === 'decoder') {
        window.HeaderDecoder?.render();
      } else if (tabName === 'telnet') {
        if (window.TelnetTerminal?.fitAddon) {
          setTimeout(() => {
            try {
              window.TelnetTerminal.fitAddon.fit();
            } catch (_) {}
          }, 50);
        }
      }
    }

    bindDashboardControls() {
      // Quick-launch protocol server toggles on Dashboard
      document.querySelectorAll('[data-dash-action]').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const action = btn.getAttribute('data-dash-action');
          switch (action) {
            case 'bootp-start':
              await window.BootpSimulator?.startServer();
              break;
            case 'bootp-stop':
              await window.BootpSimulator?.stopServer();
              break;
            case 'bootp-request':
              await window.BootpSimulator?.sendBootRequest('aa:bb:cc:dd:ee:01');
              break;
            case 'dns-start':
              await window.DnsTool?.startServer();
              break;
            case 'dns-stop':
              await window.DnsTool?.stopServer();
              break;
            case 'dns-query':
              await window.DnsTool?.executeQuery();
              break;
            case 'telnet-start':
              await window.TelnetTerminal?.startServer();
              break;
            case 'telnet-stop':
              await window.TelnetTerminal?.stopServer();
              break;
            case 'telnet-iac':
              window.TelnetTerminal?.triggerIacHandshake();
              break;
          }
        });
      });

      const demoBtn = document.getElementById('load-demo-exchange-btn');
      if (demoBtn) {
        demoBtn.addEventListener('click', () => this.loadDemoExchange(false));
      }

      const logFilter = document.getElementById('dash-log-filter');
      if (logFilter) {
        logFilter.addEventListener('change', (e) => {
          this.state.logFilter = e.target.value;
          this.renderPacketTable();
        });
      }

      const logSearch = document.getElementById('dash-log-search');
      if (logSearch) {
        logSearch.addEventListener('input', (e) => {
          this.state.logSearch = e.target.value.trim().toLowerCase();
          this.renderPacketTable();
        });
      }

      const exportJsonBtn = document.getElementById('export-json-btn');
      if (exportJsonBtn) {
        exportJsonBtn.addEventListener('click', () => this.exportPacketsJson());
      }

      const exportPcapBtn = document.getElementById('export-pcap-btn');
      if (exportPcapBtn) {
        exportPcapBtn.addEventListener('click', () => this.exportPacketsPcap());
      }

      const wsReconnectBtn = document.getElementById('ws-reconnect-btn');
      if (wsReconnectBtn) {
        wsReconnectBtn.addEventListener('click', () => this.connectPacketWebSocket());
      }
    }

    /**
     * Connect to ws://<host>/ws/packets to receive real-time packet broadcasts
     * from backend/websocket.py & logger/packet_logger.py
     */
    connectPacketWebSocket() {
      if (this.ws) {
        try {
          this.ws.close();
        } catch (_) {}
      }

      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host || 'localhost:8000';
      const url = `${proto}//${host}/ws/packets`;

      try {
        this.ws = new WebSocket(url);

        this.ws.onopen = () => {
          this.state.wsConnected = true;
          this.updateWsHeaderBadge();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.ingestPacket(data);
          } catch (err) {
            console.warn('Invalid WS packet JSON:', err);
          }
        };

        this.ws.onclose = () => {
          this.state.wsConnected = false;
          this.updateWsHeaderBadge();
        };

        this.ws.onerror = () => {
          this.state.wsConnected = false;
          this.updateWsHeaderBadge();
        };
      } catch (_) {
        this.state.wsConnected = false;
        this.updateWsHeaderBadge();
      }
    }

    updateWsHeaderBadge() {
      const dot = document.getElementById('ws-status-dot');
      const text = document.getElementById('ws-status-text');
      if (!dot || !text) return;

      if (this.state.wsConnected) {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400 status-dot-live';
        text.textContent = 'WS Live (/ws/packets)';
        text.className = 'text-xs font-mono font-semibold text-emerald-300';
      } else {
        dot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400';
        text.textContent = 'Local / Simulation Stream';
        text.className = 'text-xs font-mono font-semibold text-amber-300';
      }
    }

    /**
     * Normalize both live WebSocket events and SQLite rows from /api/<proto>/logs
     * into a single consistent packet schema.
     */
    normalizePacket(raw) {
      if (!raw) return null;
      const protocol = String(raw.protocol || 'BOOTP').toUpperCase();
      const type = String(raw.type || protocol).toUpperCase();
      const timestamp = raw.timestamp || new Date().toISOString();
      const epochMs = Date.parse(timestamp) || Date.now();

      const source = raw.source || {
        ip: raw.source_ip || '127.0.0.1',
        port: raw.source_port ?? (protocol === 'BOOTP' ? 10068 : protocol === 'DNS' ? 54321 : 51234),
      };
      const destination = raw.destination || {
        ip: raw.dest_ip || '127.0.0.1',
        port: raw.dest_port ?? (protocol === 'BOOTP' ? 10067 : protocol === 'DNS' ? 10053 : 2323),
      };

      let packetObj = raw.packet || {};
      if (typeof raw.packet_json === 'string' && raw.packet_json.trim()) {
        try {
          packetObj = JSON.parse(raw.packet_json);
        } catch (_) {}
      } else if (typeof packetObj === 'string') {
        try {
          packetObj = JSON.parse(packetObj);
        } catch (_) {}
      }

      return {
        _uid: `pkt-${this.uidCounter++}-${Math.random().toString(36).slice(2, 6)}`,
        id: raw.id || this.uidCounter,
        protocol,
        type,
        timestamp,
        _epochMs: epochMs,
        source,
        destination,
        packet: packetObj,
        raw_hex: raw.raw_hex || '',
      };
    }

    ingestPacket(rawPacket) {
      const pkt = this.normalizePacket(rawPacket);
      if (!pkt) return;

      this.state.packets.unshift(pkt);
      if (this.state.packets.length > 250) {
        this.state.packets.pop();
      }

      this.refreshAllViews();
      if (window.HeaderDecoder && !window.HeaderDecoder.currentPacket) {
        window.HeaderDecoder.inspectPacket(pkt, false);
      }
    }

    getPacketByUid(uid) {
      return this.state.packets.find((p) => p._uid === uid) || null;
    }

    clearPackets() {
      this.state.packets = [];
      this.refreshAllViews();
      this.showToast('Cleared packet capture buffer.', 'info');
    }

    async fetchSystemStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const body = await res.json();
        if (body.status === 'success' && body.data) {
          this.state.wsClientCount = body.data.ws_clients ?? 1;
          const statuses = body.data.protocol_statuses || [];
          statuses.forEach((st) => {
            const pName = String(st.protocol || '').toLowerCase();
            if (pName in this.state.protocols) {
              this.state.protocols[pName] = st.status;
            }
          });
          this.renderProtocolStatusCards();
        }
      } catch (_) {
        // Offline / standalone preview
      }
    }

    async fetchHistoricalLogs() {
      const endpoints = ['/api/bootp/logs?limit=50', '/api/dns/logs?limit=50', '/api/telnet/logs?limit=50'];
      const collected = [];

      for (const ep of endpoints) {
        try {
          const res = await fetch(ep);
          if (!res.ok) continue;
          const body = await res.json();
          if (body.status === 'success' && Array.isArray(body.data)) {
            body.data.forEach((row) => {
              const norm = this.normalizePacket(row);
              if (norm) collected.push(norm);
            });
          }
        } catch (_) {}
      }

      if (collected.length > 0) {
        collected.sort((a, b) => b._epochMs - a._epochMs);
        this.state.packets = collected;
        this.refreshAllViews();
      }
    }

    setProtocolStatus(protoKey, status) {
      const key = protoKey.toLowerCase();
      if (key in this.state.protocols) {
        this.state.protocols[key] = status;
        this.renderProtocolStatusCards();
      }
    }

    refreshAllViews() {
      this.renderProtocolStatusCards();
      this.renderStatsCounters();
      this.renderPacketTable();
      window.PacketVisualizer?.render();
    }

    renderProtocolStatusCards() {
      ['bootp', 'dns', 'telnet'].forEach((proto) => {
        const st = this.state.protocols[proto] || 'stopped';
        const isRunning = st === 'running';
        const badge = document.getElementById(`status-badge-${proto}`);
        if (badge) {
          badge.innerHTML = `
            <span class="w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-400 status-dot-live' : 'bg-slate-500'}"></span>
            <span>${isRunning ? 'RUNNING' : 'STOPPED'}</span>
          `;
          badge.className = `inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold border ${
            isRunning
              ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
              : 'bg-slate-800 text-slate-400 border-slate-700'
          }`;
        }
      });
    }

    renderStatsCounters() {
      const pkts = this.state.packets;
      const total = pkts.length;
      const bootpCount = pkts.filter((p) => p.protocol === 'BOOTP').length;
      const dnsCount = pkts.filter((p) => p.protocol === 'DNS').length;
      const telnetCount = pkts.filter((p) => p.protocol === 'TELNET').length;

      const setTxt = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = String(val);
      };
      setTxt('stat-total-packets', total);
      setTxt('stat-bootp-packets', bootpCount);
      setTxt('stat-dns-packets', dnsCount);
      setTxt('stat-telnet-packets', telnetCount);

      // Update distribution progress bar
      const denom = Math.max(1, total);
      const bPct = ((bootpCount / denom) * 100).toFixed(1);
      const dPct = ((dnsCount / denom) * 100).toFixed(1);
      const tPct = ((telnetCount / denom) * 100).toFixed(1);

      const bBar = document.getElementById('dist-bar-bootp');
      const dBar = document.getElementById('dist-bar-dns');
      const tBar = document.getElementById('dist-bar-telnet');
      if (bBar) bBar.style.width = `${bPct}%`;
      if (dBar) dBar.style.width = `${dPct}%`;
      if (tBar) tBar.style.width = `${tPct}%`;
    }

    renderPacketTable() {
      const tbody = document.getElementById('dash-packet-log-tbody');
      if (!tbody) return;

      const filtered = this.state.packets.filter((p) => {
        if (this.state.logFilter !== 'ALL' && p.protocol !== this.state.logFilter) return false;
        if (this.state.logSearch) {
          const hay = `${p.protocol} ${p.type} ${p.source?.ip} ${p.destination?.ip} ${JSON.stringify(
            p.packet
          )}`.toLowerCase();
          if (!hay.includes(this.state.logSearch)) return false;
        }
        return true;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="py-8 text-center text-xs text-slate-500">
              No matching packets in buffer. Trigger a protocol operation above or click "Load Demo Exchange".
            </td>
          </tr>
        `;
        return;
      }

      const protoBadgeCls = {
        BOOTP: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
        DNS: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
        TELNET: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      };

      tbody.innerHTML = filtered
        .slice(0, 80)
        .map((pkt, i) => {
          const badge = protoBadgeCls[pkt.protocol] || protoBadgeCls.BOOTP;
          const timeStr = new Date(pkt._epochMs).toLocaleTimeString([], {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          });
          const summary = window.PacketVisualizer
            ? window.PacketVisualizer.getSummarySubtitle(pkt)
            : JSON.stringify(pkt.packet);

          return `
            <tr class="border-b border-slate-800/80 hover:bg-slate-800/60 transition cursor-pointer text-xs font-mono"
                data-log-pkt-uid="${pkt._uid}">
              <td class="py-2.5 px-3 text-slate-400">${timeStr}</td>
              <td class="py-2.5 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badge}">${pkt.protocol}</span>
              </td>
              <td class="py-2.5 px-3 text-white font-semibold">${pkt.type}</td>
              <td class="py-2.5 px-3 text-slate-300">${pkt.source?.ip || '127.0.0.1'}:${pkt.source?.port ?? '—'} → ${
            pkt.destination?.ip || '127.0.0.1'
          }:${pkt.destination?.port ?? '—'}</td>
              <td class="py-2.5 px-3 text-slate-300 truncate max-w-xs">${summary}</td>
              <td class="py-2.5 px-3 text-right">
                <button class="px-2 py-1 rounded bg-sky-500/15 hover:bg-sky-500/30 text-sky-300 border border-sky-500/30 text-[11px]">
                  Decode Bits →
                </button>
              </td>
            </tr>
          `;
        })
        .join('');

      tbody.querySelectorAll('[data-log-pkt-uid]').forEach((tr) => {
        tr.addEventListener('click', () => {
          const uid = tr.getAttribute('data-log-pkt-uid');
          const pkt = this.getPacketByUid(uid);
          if (pkt && window.HeaderDecoder) {
            window.HeaderDecoder.inspectPacket(pkt, true);
          }
        });
      });
    }

    /**
     * Create RFC 951 compliant BOOTREQUEST + BOOTREPLY packet events
     */
    createSyntheticBootpPair(mac = 'aa:bb:cc:dd:ee:01', yiaddr = '192.168.1.10', xid = '0xc80846eb') {
      const now = Date.now();
      const req = {
        protocol: 'BOOTP',
        type: 'BOOTREQUEST',
        timestamp: new Date(now - 120).toISOString(),
        source: { ip: '0.0.0.0', port: 10068 },
        destination: { ip: '255.255.255.255', port: 10067 },
        packet: {
          op: 1,
          op_name: 'BOOTREQUEST',
          htype: 1,
          hlen: 6,
          hops: 0,
          xid,
          secs: 0,
          flags: '0x8000',
          ciaddr: '0.0.0.0',
          yiaddr: '0.0.0.0',
          siaddr: '0.0.0.0',
          giaddr: '0.0.0.0',
          chaddr: mac,
          sname: 'bootp.group3.local',
          file: '/pxelinux.0',
          vend_hex: '63825363ff',
        },
        raw_hex: '',
      };

      const rep = {
        protocol: 'BOOTP',
        type: 'BOOTREPLY',
        timestamp: new Date(now).toISOString(),
        source: { ip: '192.168.1.1', port: 10067 },
        destination: { ip: yiaddr, port: 10068 },
        packet: {
          op: 2,
          op_name: 'BOOTREPLY',
          htype: 1,
          hlen: 6,
          hops: 0,
          xid,
          secs: 0,
          flags: '0x8000',
          ciaddr: '0.0.0.0',
          yiaddr,
          siaddr: '192.168.1.1',
          giaddr: '192.168.1.1',
          chaddr: mac,
          sname: 'bootp.group3.local',
          file: '/pxelinux.0',
          vend_hex: '638253630104ffffff000304c0a80101ff',
        },
        raw_hex: '',
      };
      return [this.normalizePacket(req), this.normalizePacket(rep)];
    }

    /**
     * Create RFC 1035 compliant DNS Query + Response packet events
     */
    createSyntheticDnsPair(
      domain = 'example.local',
      qtype = 'A',
      answers = [{ name: 'example.local', type: 'A', ttl: 3600, rdata: '192.168.1.10' }],
      recursive = true,
      rttMs = 1.42
    ) {
      const now = Date.now();
      const txId = '0x' + Math.floor(0x1000 + Math.random() * 0xefff).toString(16);
      const query = {
        protocol: 'DNS',
        type: `DNS_QUERY (${qtype})`,
        timestamp: new Date(now - 60).toISOString(),
        source: { ip: '127.0.0.1', port: 54321 },
        destination: { ip: '127.0.0.1', port: 10053 },
        packet: {
          id: txId,
          qr: 0,
          flags: recursive ? '0x0100' : '0x0000',
          qdcount: 1,
          ancount: 0,
          nscount: 0,
          arcount: 0,
          qname: domain,
          qtype,
          qclass: 'IN',
        },
        raw_hex: '',
      };

      const resp = {
        protocol: 'DNS',
        type: answers.length > 0 ? `DNS_RESPONSE (${qtype})` : 'DNS_NXDOMAIN',
        timestamp: new Date(now).toISOString(),
        source: { ip: '127.0.0.1', port: 10053 },
        destination: { ip: '127.0.0.1', port: 54321 },
        packet: {
          id: txId,
          qr: 1,
          flags: answers.length > 0 ? '0x8580' : '0x8583',
          qdcount: 1,
          ancount: answers.length,
          nscount: 1,
          arcount: 0,
          qname: domain,
          qtype,
          qclass: 'IN',
          rtt_ms: rttMs,
          answers,
          rdata: answers[0]?.rdata || 'NXDOMAIN',
        },
        raw_hex: '',
      };
      return [this.normalizePacket(query), this.normalizePacket(resp)];
    }

    /**
     * Create RFC 854 compliant Telnet IAC / command packet event
     */
    createSyntheticTelnetPacket(
      subType = 'IAC_NEGOTIATION',
      summary = 'IAC WILL ECHO · IAC DO SGA · IAC DO NAWS',
      rawBytes = [0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03, 0xff, 0xfd, 0x1f],
      sender = 'server'
    ) {
      const isServer = sender === 'server';
      const evt = {
        protocol: 'TELNET',
        type: subType,
        timestamp: new Date().toISOString(),
        source: { ip: '127.0.0.1', port: isServer ? 2323 : 51820 },
        destination: { ip: '127.0.0.1', port: isServer ? 51820 : 2323 },
        packet: {
          iac_summary: summary,
          raw_bytes: rawBytes,
        },
        raw_hex: rawBytes.map((b) => b.toString(16).padStart(2, '0')).join(' '),
      };
      return this.normalizePacket(evt);
    }

    /**
     * Populate a complete multi-protocol exchange (BOOTP + DNS + TELNET)
     * matching Section 10 ("Demo Script") of project-plan.md.
     */
    loadDemoExchange(silent = false) {
      const [bReq, bRep] = this.createSyntheticBootpPair('aa:bb:cc:dd:ee:01', '192.168.1.10', '0xc80846eb');
      const [dQuery, dResp] = this.createSyntheticDnsPair('example.local', 'A', [
        { name: 'example.local', type: 'A', ttl: 3600, rdata: '192.168.1.10' },
      ]);
      const [mxQuery, mxResp] = this.createSyntheticDnsPair('example.local', 'MX', [
        { name: 'example.local', type: 'MX', ttl: 3600, rdata: '10 mail.example.local' },
      ]);
      const tIac = this.createSyntheticTelnetPacket(
        'IAC_NEGOTIATION',
        'IAC WILL ECHO (FF FB 01) · IAC DO SGA (FF FD 03) · IAC DO NAWS (FF FD 1F)',
        [0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03, 0xff, 0xfd, 0x1f],
        'server'
      );
      const tCmd = this.createSyntheticTelnetPacket(
        'TELNET_CMD',
        'whoami (NVT ASCII CR LF)',
        [0x77, 0x68, 0x6f, 0x61, 0x6d, 0x69, 0x0d, 0x0a],
        'client'
      );

      const batch = [bReq, bRep, dQuery, dResp, mxQuery, mxResp, tIac, tCmd];
      // Add in chronological order so newest ends up on top
      batch.forEach((p, idx) => {
        p._epochMs = Date.now() - (batch.length - idx) * 350;
        p.timestamp = new Date(p._epochMs).toISOString();
        this.state.packets.unshift(p);
      });

      this.refreshAllViews();
      if (window.HeaderDecoder && bRep) {
        window.HeaderDecoder.inspectPacket(bRep, false);
      }
      if (!silent) {
        this.showToast('Loaded full RFC 951 BOOTP, RFC 1035 DNS, and RFC 854 Telnet exchange!', 'success');
      }
    }

    exportPacketsJson() {
      const payload = JSON.stringify(this.state.packets, null, 2);
      const blob = new Blob([payload], { type: 'application/json' });
      this.triggerDownload(blob, `group3_packets_${Date.now()}.json`);
      this.showToast('Exported packet capture as JSON.', 'success');
    }

    /**
     * Bonus Feature (project-plan.md §11): Export packet capture as standard binary .pcap
     * (libpcap magic 0xa1b2c3d4, LinkType=1 Ethernet + IPv4 + UDP/TCP headers + protocol payload)
     */
    exportPacketsPcap() {
      const chunks = [];
      // 24-byte PCAP Global Header
      const gh = new Uint8Array(24);
      const dv = new DataView(gh.buffer);
      dv.setUint32(0, 0xa1b2c3d4, true); // magic
      dv.setUint16(4, 2, true); // version_major
      dv.setUint16(6, 4, true); // version_minor
      dv.setInt32(8, 0, true); // thiszone
      dv.setUint32(12, 0, true); // sigfigs
      dv.setUint32(16, 65535, true); // snaplen
      dv.setUint32(20, 1, true); // network = LINKTYPE_ETHERNET
      chunks.push(gh);

      const pkts = this.state.packets.slice().reverse();
      pkts.forEach((pkt) => {
        const payloadBytes = window.HeaderDecoder
          ? window.HeaderDecoder.extractBytes(pkt)
          : [0x01, 0x02, 0x03, 0x04];
        const frameLen = 14 + 20 + 8 + payloadBytes.length;
        const rec = new Uint8Array(16 + frameLen);
        const rdv = new DataView(rec.buffer);

        const tsSec = Math.floor((pkt._epochMs || Date.now()) / 1000);
        const tsUsec = ((pkt._epochMs || Date.now()) % 1000) * 1000;
        rdv.setUint32(0, tsSec, true);
        rdv.setUint32(4, tsUsec, true);
        rdv.setUint32(8, frameLen, true);
        rdv.setUint32(12, frameLen, true);

        // Ethernet II header (14B) -> EtherType 0x0800 (IPv4)
        rec[16 + 12] = 0x08;
        rec[16 + 13] = 0x00;

        // Minimal IPv4 header (20B) at offset 30
        const ipOff = 30;
        rec[ipOff] = 0x45;
        rdv.setUint16(ipOff + 2, 20 + 8 + payloadBytes.length, false);
        rec[ipOff + 8] = 64; // TTL
        rec[ipOff + 9] = pkt.protocol === 'TELNET' ? 6 : 17; // TCP(6) or UDP(17)
        // Source & Dest IP (127.0.0.1 default)
        rec.set([127, 0, 0, 1], ipOff + 12);
        rec.set([127, 0, 0, 1], ipOff + 16);

        // Transport header (8B UDP stub) at offset 50
        const trOff = 50;
        rdv.setUint16(trOff, Number(pkt.source?.port || 10068), false);
        rdv.setUint16(trOff + 2, Number(pkt.destination?.port || 10067), false);
        rdv.setUint16(trOff + 4, 8 + payloadBytes.length, false);

        // Protocol bytes at offset 58
        rec.set(payloadBytes, 58);
        chunks.push(rec);
      });

      const blob = new Blob(chunks, { type: 'application/vnd.tcpdump.pcap' });
      this.triggerDownload(blob, `group3_capture_${Date.now()}.pcap`);
      this.showToast('Exported Wireshark-compatible .pcap capture file!', 'success');
    }

    triggerDownload(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1500);
    }

    showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      if (!container) return;

      const styles = {
        success: 'border-emerald-500/50 bg-emerald-950/90 text-emerald-200',
        error: 'border-rose-500/50 bg-rose-950/90 text-rose-200',
        warning: 'border-amber-500/50 bg-amber-950/90 text-amber-200',
        info: 'border-sky-500/50 bg-slate-900/95 text-sky-200',
      };

      const toast = document.createElement('div');
      toast.className = `px-4 py-2.5 rounded-lg border shadow-xl text-xs font-medium transition-all duration-300 ${
        styles[type] || styles.info
      }`;
      toast.textContent = message;
      container.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 3400);
    }
  }

  window.VisualizerApp = new VisualizerApp();
  document.addEventListener('DOMContentLoaded', () => {
    window.VisualizerApp.init();
  });
})();
