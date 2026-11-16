from __future__ import annotations

from fastapi import APIRouter
from backend.models import ApiResponse
from logger.packet_logger import PacketLogger
from telnet.bridge import TelnetServerManager

router = APIRouter(prefix="/api/telnet", tags=["Telnet"])


@router.post("/start-server", response_model=ApiResponse)
async def start_server() -> ApiResponse:
    ok, msg = await TelnetServerManager.start(port=2323, bind_addr="0.0.0.0")
    if ok:
        db = PacketLogger.get_instance()._db
        if db:
            await db.update_protocol_status("telnet", "running")
        return ApiResponse(status="success", message=msg)
    return ApiResponse(status="error", message=msg)


@router.post("/stop-server", response_model=ApiResponse)
async def stop_server() -> ApiResponse:
    ok, msg = TelnetServerManager.stop()
    db = PacketLogger.get_instance()._db
    if ok and db:
        await db.update_protocol_status("telnet", "stopped")
    return ApiResponse(status="success" if ok else "error", message=msg)


@router.get("/sessions", response_model=ApiResponse)
async def get_sessions() -> ApiResponse:
    return ApiResponse(status="success", message="Active sessions.", data=TelnetServerManager.get_sessions())


@router.get("/logs", response_model=ApiResponse)
async def get_logs(limit: int = 100) -> ApiResponse:
    db = PacketLogger.get_instance()._db
    if db is None:
        return ApiResponse(status="error", message="Database not initialised.")
    packets = await db.get_packets(protocol="telnet", limit=limit)
    return ApiResponse(status="success", message=f"{len(packets)} log(s) retrieved.", data=packets)