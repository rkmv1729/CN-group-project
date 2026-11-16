/**
 * Group 3 — Protocol Visualizer (Roll 27)
 * Module: BOOTP Simulator & IP Pool Visualizer (frontend/js/bootp-simulator.js)
 *
 * Connects to Roll 08's BOOTP REST API (/api/bootp/start-server, /stop-server,
 * /send-request, /pool, /allocations, /logs) and renders an interactive visual
 * IP address pool grid (192.168.1.100–200 + static reservations), editable static
 * MAC-to-IP mapping table, and step-by-step RFC 951 BOOTREQUEST -> BOOTREPLY pipeline.
 */

(function () {
  'use strict';

  class BootpSimulator {
    constructor() {
      this.poolConfig = {
        server_ip: '192.168.1.1',
        gateway_ip: '192.168.1.1',
        subnet_mask: '255.255.255.0',
        pool_start: '192.168.1.100',
        pool_end: '192.168.1.200',
        static_mappings: {
          'aa:bb:cc:dd:ee:01': '192.168.1.10',
          'aa:bb:cc:dd:ee:02': '192.168.1.20',
          'aa:bb:cc:dd:ee:03': '192.168.1.30',
        },
      };
      this.allocations = {};
      this.lastReply = null;
      this.dynamicCounter = 100;
    }

    async init() {
      this.bindEvents();
      await this.refreshPoolAndAllocations();
      this.renderPoolGrid();
      this.renderStaticMappings();
    }

    bindEvents() {
      const startBtn = document.getElementById('bootp-start-btn');
      if (startBtn) {
        startBtn.addEventListener('click', () => this.startServer());
      }

      const stopBtn = document.getElementById('bootp-stop-btn');
      if (stopBtn) {
        stopBtn.addEventListener('click', () => this.stopServer());
      }

      const sendBtn = document.getElementById('bootp-send-request-btn');
      if (sendBtn) {
        sendBtn.addEventListener('click', () => {
          const macInput = document.getElementById('bootp-mac-input');
          const mac = macInput ? macInput.value.trim() : '';
          this.sendBootRequest(mac || null);
        });
      }

      const randMacBtn = document.getElementById('bootp-random-mac-btn');
      if (randMacBtn) {
        randMacBtn.addEventListener('click', () => {
          const macInput = document.getElementById('bootp-mac-input');
          if (macInput) {
            macInput.value = this.generateRandomMac();
          }
        });
      }

      document.querySelectorAll('[data-preset-mac]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const mac = btn.getAttribute('data-preset-mac');
          const macInput = document.getElementById('bootp-mac-input');
          if (macInput && mac) {
            macInput.value = mac;
          }
        });
      });

      const addStaticForm = document.getElementById('bootp-add-static-form');
      if (addStaticForm) {
        addStaticForm.addEventListener('submit', (e) => {
          e.preventDefault();
          const macEl = document.getElementById('bootp-new-static-mac');
          const ipEl = document.getElementById('bootp-new-static-ip');
          const mac = (macEl?.value || '').trim().toLowerCase();
          const ip = (ipEl?.value || '').trim();
          if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(mac)) {
            window.VisualizerApp?.showToast('Enter a valid 6-octet MAC address (e.g. aa:bb:cc:dd:ee:04)', 'error');
            return;
          }
          if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
            window.VisualizerApp?.showToast('Enter a valid IPv4 address (e.g. 192.168.1.40)', 'error');
            return;
          }
          if (!this.poolConfig.static_mappings) this.poolConfig.static_mappings = {};
          this.poolConfig.static_mappings[mac] = ip;
          if (macEl) macEl.value = '';
          if (ipEl) ipEl.value = '';
          this.renderStaticMappings();
          this.renderPoolGrid();
          window.VisualizerApp?.showToast(`Added static mapping ${mac} → ${ip}`, 'success');
        });
      }
    }

    generateRandomMac() {
      const hex = () =>
        Math.floor(Math.random() * 256)
          .toString(16)
          .padStart(2, '0');
      return `02:${hex()}:${hex()}:${hex()}:${hex()}:${hex()}`;
    }

    async refreshPoolAndAllocations() {
      try {
        const poolRes = await fetch('/api/bootp/pool');
        if (poolRes.ok) {
          const body = await poolRes.json();
          if (body.status === 'success' && body.data) {
            this.poolConfig = {
              ...this.poolConfig,
              ...body.data,
              static_mappings: {
                ...this.poolConfig.static_mappings,
                ...(body.data.static_mappings || {}),
              },
            };
          }
        }
      } catch (_) {
        // Offline or standalone demo mode; keep default poolConfig
      }

      try {
        const allocRes = await fetch('/api/bootp/allocations');
        if (allocRes.ok) {
          const body = await allocRes.json();
          if (body.status === 'success' && body.data) {
            this.allocations = { ...this.allocations, ...body.data };
          }
        }
      } catch (_) {
        // Ignore when offline
      }

      this.syncConfigInputs();
      this.renderPoolGrid();
      this.renderStaticMappings();
    }

    syncConfigInputs() {
      const fields = {
        'bootp-cfg-server-ip': this.poolConfig.server_ip || '192.168.1.1',
        'bootp-cfg-gateway-ip': this.poolConfig.gateway_ip || '192.168.1.1',
        'bootp-cfg-pool-start': this.poolConfig.pool_start || '192.168.1.100',
        'bootp-cfg-pool-end': this.poolConfig.pool_end || '192.168.1.200',
      };
      Object.entries(fields).forEach(([id, val]) => {
        const el = document.getElementById(id);
        if (el && !el.matches(':focus')) el.value = val;
      });
    }

    async startServer() {
      const cfg = {
        server_ip: document.getElementById('bootp-cfg-server-ip')?.value || '192.168.1.1',
        gateway_ip: document.getElementById('bootp-cfg-gateway-ip')?.value || '192.168.1.1',
        pool_start: document.getElementById('bootp-cfg-pool-start')?.value || '192.168.1.100',
        pool_end: document.getElementById('bootp-cfg-pool-end')?.value || '192.168.1.200',
      };

      try {
        const res = await fetch('/api/bootp/start-server', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cfg),
        });
        const body = await res.json();
        if (body.status === 'success' || (body.message && body.message.includes('already running'))) {
          window.VisualizerApp?.setProtocolStatus('bootp', 'running');
          window.VisualizerApp?.showToast('BOOTP Server listening on UDP port 10067', 'success');
          await this.refreshPoolAndAllocations();
          return;
        }
        window.VisualizerApp?.showToast(body.message || 'Could not start BOOTP server', 'warning');
      } catch (_) {
        // Fallback for standalone preview
        window.VisualizerApp?.setProtocolStatus('bootp', 'running');
        window.VisualizerApp?.showToast('BOOTP Server started (Simulation Mode — UDP :10067)', 'info');
      }
    }

    async stopServer() {
      try {
        const res = await fetch('/api/bootp/stop-server', { method: 'POST' });
        const body = await res.json();
        window.VisualizerApp?.setProtocolStatus('bootp', 'stopped');
        window.VisualizerApp?.showToast(body.message || 'BOOTP server stopped.', 'info');
      } catch (_) {
        window.VisualizerApp?.setProtocolStatus('bootp', 'stopped');
        window.VisualizerApp?.showToast('BOOTP server stopped.', 'info');
      }
    }

    async sendBootRequest(macAddress = null) {
      const mac = (macAddress || document.getElementById('bootp-mac-input')?.value || 'aa:bb:cc:dd:ee:01')
        .trim()
        .toLowerCase();

      this.animateExchangeStep(1);

      try {
        const url = `/api/bootp/send-request?mac_address=${encodeURIComponent(mac)}`;
        const res = await fetch(url, { method: 'POST' });
        const body = await res.json();

        if (body.status === 'success' && body.data) {
          this.animateExchangeStep(4);
          this.lastReply = body.data;
          if (body.data.chaddr && body.data.yiaddr) {
            this.allocations[body.data.chaddr.toLowerCase()] = body.data.yiaddr;
          }
          await this.refreshPoolAndAllocations();
          this.renderExchangeResult(body.data);
          window.VisualizerApp?.showToast(
            `BOOTREPLY received: ${mac} leased ${body.data.yiaddr} (xid=${body.data.xid})`,
            'success'
          );
          return;
        }
      } catch (_) {
        // Fall through to local RFC 951 packet exchange generator if backend isn't reachable
      }

      // Local RFC 951 exchange fallback (or if server wasn't started yet)
      const [reqPkt, repPkt] = this.simulateLocalBootpExchange(mac);
      window.VisualizerApp?.ingestPacket(reqPkt);
      setTimeout(() => {
        window.VisualizerApp?.ingestPacket(repPkt);
        this.animateExchangeStep(4);
        this.lastReply = repPkt.packet;
        this.renderExchangeResult(repPkt.packet);
        this.renderPoolGrid();
        window.VisualizerApp?.showToast(
          `BOOTREPLY: Assigned yiaddr=${repPkt.packet.yiaddr} to MAC ${mac}`,
          'success'
        );
      }, 240);
    }

    simulateLocalBootpExchange(mac) {
      const cleanMac = mac || 'aa:bb:cc:dd:ee:01';
      const xid = '0x' + Math.floor(0x10000000 + Math.random() * 0xefffffff).toString(16);
      const staticMap = this.poolConfig.static_mappings || {};
      let assignedIp = staticMap[cleanMac] || this.allocations[cleanMac];
      if (!assignedIp) {
        const usedIps = new Set([...Object.values(staticMap), ...Object.values(this.allocations)]);
        while (usedIps.has(`192.168.1.${this.dynamicCounter}`) && this.dynamicCounter < 200) {
          this.dynamicCounter++;
        }
        assignedIp = `192.168.1.${this.dynamicCounter}`;
      }
      this.allocations[cleanMac] = assignedIp;

      return window.VisualizerApp.createSyntheticBootpPair(cleanMac, assignedIp, xid);
    }

    animateExchangeStep(finalStep = 4) {
      for (let s = 1; s <= 4; s++) {
        const el = document.getElementById(`bootp-step-${s}`);
        if (!el) continue;
        el.classList.remove('border-sky-500', 'bg-sky-950/40');
        setTimeout(() => {
          if (s <= finalStep) {
            el.classList.add('border-sky-500', 'bg-sky-950/40');
          }
        }, s * 70);
      }
    }

    renderExchangeResult(replyData) {
      const box = document.getElementById('bootp-last-reply-card');
      if (!box || !replyData) return;

      const isStatic =
        this.poolConfig.static_mappings &&
        this.poolConfig.static_mappings[(replyData.chaddr || '').toLowerCase()] === replyData.yiaddr;

      box.innerHTML = `
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div class="bg-slate-900/90 border border-slate-800 rounded-lg p-3">
            <div class="text-[11px] text-slate-400 uppercase font-mono">Assigned IP (yiaddr)</div>
            <div class="text-base font-bold font-mono text-emerald-400 mt-0.5">${replyData.yiaddr || '0.0.0.0'}</div>
            <span class="inline-block mt-1 px-1.5 py-0.5 text-[10px] font-semibold rounded ${
              isStatic
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30'
                : 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
            }">${isStatic ? 'Static Reservation' : 'Dynamic Pool Lease'}</span>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 rounded-lg p-3">
            <div class="text-[11px] text-slate-400 uppercase font-mono">Client MAC (chaddr)</div>
            <div class="text-sm font-bold font-mono text-amber-300 mt-1">${replyData.chaddr || '—'}</div>
            <div class="text-[11px] text-slate-500 font-mono mt-1">htype=1 (Ethernet) · hlen=6</div>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 rounded-lg p-3">
            <div class="text-[11px] text-slate-400 uppercase font-mono">Transaction ID (xid)</div>
            <div class="text-sm font-bold font-mono text-sky-300 mt-1">${replyData.xid || '—'}</div>
            <div class="text-[11px] text-slate-500 font-mono mt-1">flags=${replyData.flags || '0x8000'}</div>
          </div>
          <div class="bg-slate-900/90 border border-slate-800 rounded-lg p-3">
            <div class="text-[11px] text-slate-400 uppercase font-mono">Server / Gateway</div>
            <div class="text-xs font-mono text-slate-200 mt-1">siaddr: ${replyData.siaddr || this.poolConfig.server_ip}</div>
            <div class="text-xs font-mono text-slate-400 mt-0.5">giaddr: ${replyData.giaddr || this.poolConfig.gateway_ip}</div>
          </div>
        </div>
      `;
    }

    renderStaticMappings() {
      const tbody = document.getElementById('bootp-static-table-body');
      if (!tbody) return;

      const staticMap = this.poolConfig.static_mappings || {};
      const entries = Object.entries(staticMap);

      if (entries.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="py-4 text-center text-xs text-slate-500">No static reservations configured.</td></tr>`;
        return;
      }

      tbody.innerHTML = entries
        .map(([mac, ip]) => {
          const isActive = this.allocations[mac.toLowerCase()] === ip;
          return `
            <tr class="border-b border-slate-800/80 hover:bg-slate-800/40 text-xs font-mono">
              <td class="py-2 px-3 text-amber-300">${mac}</td>
              <td class="py-2 px-3 text-emerald-400 font-semibold">${ip}</td>
              <td class="py-2 px-3">
                <span class="px-2 py-0.5 rounded text-[10px] font-semibold ${
                  isActive
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-slate-800 text-slate-400'
                }">
                  ${isActive ? 'Leased / Active' : 'Reserved'}
                </span>
              </td>
              <td class="py-2 px-3 text-right">
                <button class="px-2 py-1 rounded bg-sky-600/20 hover:bg-sky-600/40 text-sky-300 border border-sky-500/30 text-[11px]"
                        data-Request-mac="${mac}">
                  Test Boot →
                </button>
              </td>
            </tr>
          `;
        })
        .join('');

      tbody.querySelectorAll('[data-Request-mac]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const mac = btn.getAttribute('data-Request-mac');
          const macInput = document.getElementById('bootp-mac-input');
          if (macInput) macInput.value = mac;
          this.sendBootRequest(mac);
        });
      });
    }

    renderPoolGrid() {
      const grid = document.getElementById('bootp-ip-pool-grid');
      const statsEl = document.getElementById('bootp-pool-stats');
      if (!grid) return;

      const staticMap = this.poolConfig.static_mappings || {};
      const staticIpToMac = {};
      Object.entries(staticMap).forEach(([m, ip]) => {
        staticIpToMac[ip] = m.toLowerCase();
      });

      const leasedIpToMac = {};
      Object.entries(this.allocations).forEach(([m, ip]) => {
        leasedIpToMac[ip] = m.toLowerCase();
      });

      // Build list of IPs: Static reservations first + Dynamic pool 192.168.1.100..149 (50 slots for clean visual density)
      const slots = [];
      Object.entries(staticMap).forEach(([mac, ip]) => {
        slots.push({
          ip,
          octet: ip.split('.').pop(),
          type: leasedIpToMac[ip] ? 'static-active' : 'static-reserved',
          mac,
        });
      });

      const startParts = (this.poolConfig.pool_start || '192.168.1.100').split('.');
      const prefix = startParts.slice(0, 3).join('.');
      const startOctet = parseInt(startParts[3], 10) || 100;
      const endOctet = Math.min(startOctet + 47, parseInt((this.poolConfig.pool_end || '192.168.1.200').split('.')[3], 10) || 200);

      for (let oct = startOctet; oct <= endOctet; oct++) {
        const ip = `${prefix}.${oct}`;
        if (staticIpToMac[ip]) continue;
        const boundMac = leasedIpToMac[ip] || null;
        slots.push({
          ip,
          octet: `.${oct}`,
          type: boundMac ? 'dynamic-leased' : 'free',
          mac: boundMac,
        });
      }

      const leasedCount = Object.keys(this.allocations).length;
      const staticCount = Object.keys(staticMap).length;
      if (statsEl) {
        statsEl.textContent = `${leasedCount} Active Lease(s) · ${staticCount} Static Reservation(s) · Pool ${this.poolConfig.pool_start}–${this.poolConfig.pool_end}`;
      }

      grid.innerHTML = slots
        .map((s) => {
          let cls = 'bg-slate-900/80 border-slate-800 text-slate-400 hover:border-slate-600';
          let badge = 'FREE';
          if (s.type === 'static-active') {
            cls = 'bg-purple-950/60 border-purple-500/60 text-purple-200';
            badge = 'STATIC·ACTIVE';
          } else if (s.type === 'static-reserved') {
            cls = 'bg-indigo-950/40 border-indigo-500/40 text-indigo-300';
            badge = 'STATIC';
          } else if (s.type === 'dynamic-leased') {
            cls = 'bg-emerald-950/60 border-emerald-500/60 text-emerald-200';
            badge = 'LEASED';
          }
          return `
            <div class="ip-slot border rounded-lg p-2 text-center font-mono ${cls}"
                 title="${s.ip}${s.mac ? ' → ' + s.mac : ' (Available)'}">
              <div class="text-xs font-bold">${s.ip}</div>
              <div class="text-[9px] uppercase tracking-wider opacity-80 mt-0.5">${badge}</div>
              <div class="text-[10px] truncate mt-0.5 opacity-90">${s.mac || 'unassigned'}</div>
            </div>
          `;
        })
        .join('');
    }
  }

  window.BootpSimulator = new BootpSimulator();
})();
