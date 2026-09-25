"""
SentinelBash - Real-Time Server-Sent Events (SSE) Streaming Gateway
Streams live normalized log telemetry and threat alert notifications to connected dashboards.
"""

import os
import json
import asyncio
from typing import AsyncGenerator
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/v1/stream", tags=["Real-Time SSE Gateway"])

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NORMALIZED_LOG_PATH = os.path.join(PROJECT_ROOT, "data", "logs", "normalized.log")
ALERTS_LOG_PATH = os.path.join(PROJECT_ROOT, "data", "logs", "alerts.log")


async def tail_log_stream(file_path: str, request: Request, event_name: str = "log_event") -> AsyncGenerator[str, None]:
    """Asynchronously tails an append-only log file and yields SSE formatted event payloads."""
    # Ensure log file exists
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            f.write("")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        # Seek to end of file to stream only fresh events
        f.seek(0, os.SEEK_END)

        # Emit initial connection handshake
        yield f"event: handshake\ndata: {json.dumps({'status': 'CONNECTED', 'stream': event_name})}\n\n"

        ping_counter = 0
        while True:
            # Check client disconnection
            if await request.is_disconnected():
                break

            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    # Parse pipe-delimited record: [EPOCH]|[SERVICE]|[IP]|[EVENT_TYPE]|[PAYLOAD]
                    parts = line.split("|", 4)
                    if len(parts) >= 5:
                        payload = {
                            "epoch": int(parts[0]) if parts[0].isdigit() else 0,
                            "service": parts[1],
                            "ip": parts[2],
                            "event_type": parts[3],
                            "details": parts[4],
                        }
                    else:
                        payload = {"raw": line}

                    yield f"event: {event_name}\ndata: {json.dumps(payload)}\n\n"
            else:
                await asyncio.sleep(0.5)
                ping_counter += 1
                if ping_counter >= 30:  # Ping every 15s
                    ping_counter = 0
                    yield ": ping\n\n"


@router.get("/logs")
async def stream_live_logs(request: Request):
    """Server-Sent Events endpoint streaming real-time normalized Linux security logs."""
    return StreamingResponse(
        tail_log_stream(NORMALIZED_LOG_PATH, request, event_name="log_event"),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/alerts")
async def stream_live_alerts(request: Request):
    """Server-Sent Events endpoint streaming real-time security alerts and containment events."""
    return StreamingResponse(
        tail_log_stream(ALERTS_LOG_PATH, request, event_name="alert_event"),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
