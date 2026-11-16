from __future__ import annotations

import asyncio
import logging
import os
import subprocess
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from logger.packet_logger import PacketLogger

logger = logging.getLogger(__name__)

IAC, SE, SB, WILL, WONT, DO, DONT = 255, 240, 250, 251, 252, 253, 254
ECHO, SGA, TTYPE, NAWS = 1, 3, 24, 31
CMD_NAMES = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}
INTERNAL_PORT = 2324


def _split_iac(data: bytes) -> tuple[bytes, bytes]:
    """Separate RFC 854 IAC sequences from plain terminal data."""
    text_out, iac_out, i = bytearray(), bytearray(), 0
    while i < len(data):
        if data[i] == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (WILL, WONT, DO, DONT) and i + 2 < len(data):
                iac_out.extend(data[i:i + 3])
                i += 3
            elif cmd == SB:
                end = data.find(bytes([IAC, SE]), i + 2)
                if end != -1:
                    iac_out.extend(data[i:end + 2])
                    i = end + 2
                else:
                    iac_out.extend(data[i:i + 2])
                    i += 2
            else:
                iac_out.extend(data[i:i + 2])
                i += 2
        else:
            text_out.append(data[i])
            i += 1
    return bytes(text_out), bytes(iac_out)


class TelnetServerManager:
    _proc: subprocess.Popen | None = None
    _proxy_server: asyncio.AbstractServer | None = None
    _sessions: list[dict[str, Any]] = []

    @classmethod
    def start(cls, port: int = 2323, bind_addr: str = "0.0.0.0") -> tuple[bool, str]:
        if cls._proc is not None and cls._proc.poll() is None:
            return False, "Telnet server is already running."

        bin_path = os.path.abspath("telnet/bin/telnet-server")
        if not os.path.exists(bin_path):
            return False, f"Binary not found at {bin_path}. Run 'make' inside telnet/."

        cls._proc = subprocess.Popen([bin_path, "-p", str(INTERNAL_PORT), "-b", "127.0.0.1"])
        loop = asyncio.get_running_loop()
        loop.create_task(cls._start_proxy(bind_addr, port))
        return True, f"Telnet proxy listening on {bind_addr}:{port} -> C PTY :{INTERNAL_PORT}."

    @classmethod
    async def _start_proxy(cls, bind_addr: str, port: int) -> None:
        cls._proxy_server = await asyncio.start_server(cls._handle_tcp_client, bind_addr, port)
        logger.info("Telnet logging proxy listening on %s:%d", bind_addr, port)

    @classmethod
    async def _handle_tcp_client(cls, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        peer = c_writer.get_extra_info("peername") or ("unknown", 0)
        client_ip, client_port = peer[0], peer[1]
        try:
            s_reader, s_writer = await asyncio.open_connection("127.0.0.1", INTERNAL_PORT)
        except Exception:
            c_writer.close()
            return

        session = {"host": client_ip, "port": client_port, "connected_at": datetime.now(timezone.utc).isoformat()}
        cls._sessions.append(session)
        pkt_logger = PacketLogger.get_instance()

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, from_server: bool) -> None:
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()

                    text_bytes, iac_bytes = _split_iac(data)
                    src_ep = {"ip": "127.0.0.1", "port": 2323} if from_server else {"ip": client_ip, "port": client_port}
                    dst_ep = {"ip": client_ip, "port": client_port} if from_server else {"ip": "127.0.0.1", "port": 2323}

                    if iac_bytes:
                        await pkt_logger.log_packet({
                            "protocol": "TELNET", "type": "IAC_NEGOTIATION",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source": src_ep, "destination": dst_ep,
                            "packet": {"iac_summary": f"IAC ({len(iac_bytes)}B)", "raw_bytes": list(iac_bytes)},
                            "raw_hex": " ".join(f"{b:02x}" for b in iac_bytes),
                        })
                    if text_bytes:
                        preview = text_bytes.decode("utf-8", errors="replace").strip()[:50]
                        await pkt_logger.log_packet({
                            "protocol": "TELNET", "type": "TELNET_OUTPUT" if from_server else "TELNET_CMD",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "source": src_ep, "destination": dst_ep,
                            "packet": {"iac_summary": preview or "Data", "raw_bytes": list(text_bytes)},
                            "raw_hex": " ".join(f"{b:02x}" for b in text_bytes),
                        })
            except Exception:
                pass

        await asyncio.gather(pipe(c_reader, s_writer, False), pipe(s_reader, c_writer, True), return_exceptions=True)
        if session in cls._sessions:
            cls._sessions.remove(session)
        c_writer.close()
        s_writer.close()

    @classmethod
    def stop(cls) -> tuple[bool, str]:
        if cls._proxy_server is not None:
            cls._proxy_server.close()
            cls._proxy_server = None
        if cls._proc is None or cls._proc.poll() is not None:
            cls._proc = None
            return False, "Telnet server is not running."
        cls._proc.terminate()
        cls._proc.wait(timeout=3)
        cls._proc = None
        return True, "Telnet server stopped."

    @classmethod
    def get_sessions(cls) -> list[dict[str, Any]]:
        return list(cls._sessions)


async def bridge_ws_to_telnet(websocket: WebSocket, pkt_logger: Any, port: int = INTERNAL_PORT) -> None:
    await websocket.accept()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
    except Exception as exc:
        await websocket.send_json({
            "output": f"\r\n[Telnet Bridge] Cannot connect to 127.0.0.1:{port} ({exc}). Click 'Start (:2323)' first.\r\n"
        })
        await websocket.close()
        return

    async def log_frame(ptype: str, summary: str, raw: bytes, from_server: bool) -> None:
        await pkt_logger.log_packet({
            "protocol": "TELNET", "type": ptype,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {"ip": "127.0.0.1", "port": 2323 if from_server else 51820},
            "destination": {"ip": "127.0.0.1", "port": 51820 if from_server else 2323},
            "packet": {"iac_summary": summary, "raw_bytes": list(raw)},
            "raw_hex": " ".join(f"{b:02x}" for b in raw),
        })

    async def tcp_to_ws() -> None:
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                text_out, iac_bytes, i = bytearray(), bytearray(), 0
                while i < len(data):
                    if data[i] == IAC and i + 1 < len(data):
                        cmd = data[i + 1]
                        if cmd in (WILL, WONT, DO, DONT) and i + 2 < len(data):
                            opt = data[i + 2]
                            seq = bytes([IAC, cmd, opt])
                            iac_bytes.extend(seq)
                            if cmd == WILL and opt in (ECHO, SGA):
                                writer.write(bytes([IAC, DO, opt]))
                            elif cmd == DO and opt in (SGA, NAWS, TTYPE):
                                writer.write(bytes([IAC, WILL, opt]))
                                if opt == NAWS:
                                    writer.write(bytes([IAC, SB, NAWS, 0, 84, 0, 20, IAC, SE]))
                            await writer.drain()
                            await websocket.send_json({
                                "iac": {"direction": "S → C", "bytes": seq.hex(" ").upper(),
                                        "desc": f"IAC {CMD_NAMES.get(cmd, cmd)} Opt {opt}"}
                            })
                            i += 3
                        elif cmd == SB:
                            end = data.find(bytes([IAC, SE]), i + 2)
                            if end != -1:
                                if i + 2 < len(data) and data[i + 2] == TTYPE:
                                    writer.write(bytes([IAC, SB, TTYPE, 0]) + b"xterm-256color" + bytes([IAC, SE]))
                                    await writer.drain()
                                iac_bytes.extend(data[i:end + 2])
                                i = end + 2
                            else:
                                i += 2
                        else:
                            i += 2
                    else:
                        text_out.append(data[i])
                        i += 1
                if iac_bytes:
                    await log_frame("IAC_NEGOTIATION", f"IAC ({len(iac_bytes)}B)", bytes(iac_bytes), True)
                if text_out:
                    decoded = text_out.decode("utf-8", errors="replace")
                    await websocket.send_json({"output": decoded})
                    await log_frame("TELNET_OUTPUT", decoded.strip()[:50] or "PTY output", bytes(text_out), True)
        except Exception:
            pass

    async def ws_to_tcp() -> None:
        try:
            while True:
                msg = await websocket.receive_text()
                raw = msg.replace("\r", "\r\n").encode("utf-8")
                writer.write(raw)
                await writer.drain()
                await log_frame("TELNET_CMD", msg.strip()[:50] or "Keystroke", raw, False)
        except WebSocketDisconnect:
            pass

    await asyncio.gather(tcp_to_ws(), ws_to_tcp(), return_exceptions=True)
    writer.close()