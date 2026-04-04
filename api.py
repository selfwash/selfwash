"""
Read-only HTTP API for Lovable / frontends. Reads PostgreSQL filled by consumer.py.
Set on Railway (second service): Start Command = uvicorn api:app --host 0.0.0.0 --port $PORT
"""

from __future__ import annotations

import os
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import desc, select
from sqlalchemy.orm import Session, selectinload

load_dotenv()

from db import NayaxTransaction, NayaxTransactionProduct, SessionLocal, init_db

READ_API_KEY = os.environ.get("READ_API_KEY", "").strip()


def _cors_origins() -> list[str]:
    raw = os.environ.get("CORS_ORIGINS", "*").strip()
    if raw == "*":
        return ["*"]
    return [o.strip() for o in raw.split(",") if o.strip()]


_origins = _cors_origins()
_cors_credentials = False if _origins == ["*"] else True

app = FastAPI(title="SelfWash API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def _optional_api_key(request: Request, call_next: Any) -> Any:
    if request.method == "OPTIONS":
        return await call_next(request)
    path = request.url.path
    if READ_API_KEY and path.startswith("/api"):
        if request.headers.get("X-API-Key") != READ_API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Invalid or missing X-API-Key"})
    return await call_next(request)


def get_db() -> Any:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def _startup() -> None:
    init_db()


def _dec(v: Optional[Decimal]) -> Optional[float]:
    if v is None:
        return None
    return float(v)


def _tx_summary(row: NayaxTransaction) -> dict[str, Any]:
    return {
        "id": row.id,
        "nayax_transaction_id": row.nayax_transaction_id,
        "site_id": row.site_id,
        "machine_id": row.machine_id,
        "currency": row.currency,
        "se_value": _dec(row.se_value),
        "authorization_value": _dec(row.authorization_value),
        "payed_value": _dec(row.payed_value),
        "machine_name": row.machine_name,
        "payment_method_description": row.payment_method_description,
        "settlement_time": row.settlement_time,
        "void": row.void,
        "received_at": row.received_at.isoformat() if row.received_at else None,
    }


def _product_line(p: NayaxTransactionProduct) -> dict[str, Any]:
    return {
        "line_index": p.line_index,
        "product_name": p.product_name,
        "product_group": p.product_group,
        "product_pa_code": p.product_pa_code,
        "amount_bruto": _dec(p.amount_bruto),
        "payload_json": p.payload_json,
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/transactions")
def list_transactions(
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    q = (
        select(NayaxTransaction)
        .order_by(desc(NayaxTransaction.received_at))
        .offset(offset)
        .limit(limit)
    )
    rows = list(db.scalars(q).all())
    return {
        "items": [_tx_summary(r) for r in rows],
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/transactions/{row_id}")
def get_transaction(row_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = db.scalar(
        select(NayaxTransaction)
        .options(selectinload(NayaxTransaction.products))
        .where(NayaxTransaction.id == row_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    products = sorted(row.products, key=lambda p: p.line_index)
    return {
        **_tx_summary(row),
        "payload_json": row.payload_json,
        "products": [_product_line(p) for p in products],
    }
