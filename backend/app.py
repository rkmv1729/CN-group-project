"""Main FastAPI application — Protocol Visualizer (Group 3).

Composes all routers, sets up middleware, and wires the database,
packet logger, and WebSocket manager together.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.models import ApiResponse
from backend.routes import bootp_routes, dns_routes, telnet_routes
from backend.websocket import WebSocketManager
from logger.db import PacketDatabase
from logger.packet_logger import PacketLogger

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared instances
# ---------------------------------------------------------------------------
db = PacketDatabase(db_path="data/packets.db")
ws_manager = WebSocketManager()
pkt_logger = PacketLogger.get_instance()


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler — initialises DB, logger, and event loop ref."""
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)

    # Database
    await db.init()
    logger.info("PacketDatabase initialised.")

    # Packet logger
    pkt_logger.set_database(db)
    pkt_logger.set_event_loop(asyncio.get_running_loop())
    pkt_logger.register_ws_callback(ws_manager.broadcast)
    logger.info("PacketLogger wired to DB and WebSocket manager.")

    yield  # Application runs here

    logger.info("Shutting down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Protocol Visualizer — Group 3",
    description="Real-time BOOTP / DNS / Telnet packet capture and visualisation.",
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS (for development — allows any origin)
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(bootp_routes.router)
app.include_router(dns_routes.router)
app.include_router(telnet_routes.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/status", response_model=ApiResponse, tags=["System"])
async def health_check() -> ApiResponse:
    """Health-check endpoint.

    Returns:
        An :class:`ApiResponse` with DB stats and WebSocket client count.
    """
    stats = await db.get_stats()
    return ApiResponse(
        status="success",
        message="Protocol Visualizer is running.",
        data={
            "ws_clients": ws_manager.client_count,
            **stats,
        },
    )


# ---------------------------------------------------------------------------
# WebSocket endpoints
# ---------------------------------------------------------------------------
@app.websocket("/ws/packets")
async def ws_packets(websocket: WebSocket) -> None:
    """Live packet-stream WebSocket.

    Clients connect here to receive real-time JSON packet events pushed
    by the :class:`WebSocketManager`.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; we don't expect client messages
            # but we must await to detect disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


@app.websocket("/ws/telnet")
async def ws_telnet(websocket: WebSocket) -> None:
    from telnet.bridge import bridge_ws_to_telnet
    await bridge_ws_to_telnet(websocket, pkt_logger)


# ---------------------------------------------------------------------------
# Static files — serves the frontend SPA
# ---------------------------------------------------------------------------
# Mount LAST so API routes take priority.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
