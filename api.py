"""
Read-only HTTP API for Lovable / dashboards. Uses the same db engine as consumer.py. Railway: DATABASE_URL must reference PostgreSQL (persistent).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, time, timezone
from decimal import Decimal
from typing import Any, Optional
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from requests import RequestException
from sqlalchemy import and_, asc, desc, func, select
from sqlalchemy.orm import Session, selectinload

load_dotenv()

from db import NayaxTransaction, NayaxTransactionProduct, SessionLocal, init_db
from iot_service import close_machine_order, create_machine_order, get_machine_state, start_machine

READ_API_KEY = os.environ.get("READ_API_KEY", "").strip()

_TZ_ISRAEL = ZoneInfo("Asia/Jerusalem")


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return _as_utc(dt).isoformat()


def _iso_israel(dt: Optional[datetime]) -> Optional[str]:
    """Israel civil time (DST-aware via IANA zone)."""
    if dt is None:
        return None
    return _as_utc(dt).astimezone(_TZ_ISRAEL).isoformat()


# Every scalar column we expose on each transaction (plus identifiers + optional payload/products).
TRANSACTION_FIELD_KEYS = [
    "identifiers",
    "id",
    "sqs_message_id",
    "nayax_transaction_id",
    "remote_start_transaction_id",
    "payment_method_id",
    "site_id",
    "machine_id",
    "machine_time",
    "void",
    "currency",
    "se_value",
    "authorization_value",
    "payed_value",
    "settlement_time",
    "authorization_time",
    "pay_serv_trans_id",
    "authorization_rrn",
    "payment_method_description",
    "recognition_description",
    "machine_name",
    "machine_group",
    "operator_identifier",
    "actor_id",
    "actor_description",
    "location_code",
    "location_description",
    "area_description",
    "consumer_id",
    "card_first_4",
    "card_last_4",
    "display_card_number",
    "card_type",
    "received_at",
    "received_at_utc",
]


def _identifiers(row: NayaxTransaction) -> dict[str, Any]:
    """Stable IDs for dashboards — Nayax business id + our row id + related refs."""
    return {
        "row_id": row.id,
        "nayax_transaction_id": row.nayax_transaction_id,
        "remote_start_transaction_id": row.remote_start_transaction_id,
        "pay_serv_trans_id": row.pay_serv_trans_id,
        "authorization_rrn": row.authorization_rrn,
        "sqs_message_id": row.sqs_message_id,
    }


def _cors_origins() -> list[str]:
    raw = os.environ.get("CORS_ORIGINS", "*").strip()
    if raw == "*":
        return ["*"]
    origins = [o.strip() for o in raw.split(",") if o.strip()]

    # Optional Lovable-specific origins can be appended without replacing CORS_ORIGINS.
    lovable_origin = os.environ.get("LOVABLE_ORIGIN", "").strip()
    if lovable_origin:
        origins.append(lovable_origin)
    lovable_origins_raw = os.environ.get("LOVABLE_ORIGINS", "").strip()
    if lovable_origins_raw:
        origins.extend([o.strip() for o in lovable_origins_raw.split(",") if o.strip()])

    # De-duplicate while preserving order.
    return list(dict.fromkeys(origins))


_origins = _cors_origins()
_cors_credentials = False if _origins == ["*"] else True

app = FastAPI(title="SelfWash API", version="1.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=_cors_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
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


def _parse_instant(s: str) -> datetime:
    """ISO8601 or YYYY-MM-DD (UTC midnight start of day)."""
    s = s.strip()
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _parse_end_of_day(s: str) -> datetime:
    """Inclusive end for YYYY-MM-DD on received_at."""
    s = s.strip()
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        d = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.combine(d.date(), time(23, 59, 59, 999999), tzinfo=timezone.utc)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _tx_full(
    row: NayaxTransaction,
    *,
    include_payload: bool = True,
    parse_payload: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "identifiers": _identifiers(row),
        "id": row.id,
        "sqs_message_id": row.sqs_message_id,
        "nayax_transaction_id": row.nayax_transaction_id,
        "remote_start_transaction_id": row.remote_start_transaction_id,
        "payment_method_id": row.payment_method_id,
        "site_id": row.site_id,
        "machine_id": row.machine_id,
        "machine_time": row.machine_time,
        "void": row.void,
        "currency": row.currency,
        "se_value": _dec(row.se_value),
        "authorization_value": _dec(row.authorization_value),
        "payed_value": _dec(row.payed_value),
        "settlement_time": row.settlement_time,
        "authorization_time": row.authorization_time,
        "pay_serv_trans_id": row.pay_serv_trans_id,
        "authorization_rrn": row.authorization_rrn,
        "payment_method_description": row.payment_method_description,
        "recognition_description": row.recognition_description,
        "machine_name": row.machine_name,
        "machine_group": row.machine_group,
        "operator_identifier": row.operator_identifier,
        "actor_id": row.actor_id,
        "actor_description": row.actor_description,
        "location_code": row.location_code,
        "location_description": row.location_description,
        "area_description": row.area_description,
        "consumer_id": row.consumer_id,
        "card_first_4": row.card_first_4,
        "card_last_4": row.card_last_4,
        "display_card_number": row.display_card_number,
        "card_type": row.card_type,
        "received_at": _iso_israel(row.received_at),
        "received_at_utc": _iso_utc(row.received_at),
    }
    if include_payload:
        raw = row.payload_json
        if parse_payload:
            try:
                out["payload"] = json.loads(raw)
            except json.JSONDecodeError:
                out["payload"] = None
                out["payload_json"] = raw
        else:
            out["payload_json"] = raw
    return out


def _product_line(p: NayaxTransactionProduct) -> dict[str, Any]:
    return {
        "id": p.id,
        "line_index": p.line_index,
        "product_name": p.product_name,
        "product_group": p.product_group,
        "product_pa_code": p.product_pa_code,
        "product_code_in_map": p.product_code_in_map,
        "amount_bruto": _dec(p.amount_bruto),
        "discount_amount": _dec(p.discount_amount),
        "discount_percentage": _dec(p.discount_percentage),
        "payload_json": p.payload_json,
    }


def _filter_conditions(
    *,
    from_date: Optional[str],
    to_date: Optional[str],
    since: Optional[str],
    site_id: Optional[int],
    machine_id: Optional[int],
    nayax_transaction_id: Optional[int],
) -> list[Any]:
    cond: list[Any] = []
    if from_date:
        cond.append(NayaxTransaction.received_at >= _parse_instant(from_date))
    if to_date:
        cond.append(NayaxTransaction.received_at <= _parse_end_of_day(to_date))
    if since:
        cond.append(NayaxTransaction.received_at > _parse_instant(since))
    if site_id is not None:
        cond.append(NayaxTransaction.site_id == site_id)
    if machine_id is not None:
        cond.append(NayaxTransaction.machine_id == machine_id)
    if nayax_transaction_id is not None:
        cond.append(NayaxTransaction.nayax_transaction_id == nayax_transaction_id)
    return cond


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


class StartMachineRequest(BaseModel):
    device_sn: str
    prepay_money: float


class CreateOrderRequest(BaseModel):
    prepay_money: float


class CloseOrderRequest(BaseModel):
    order_id: Optional[str] = None


@app.post("/api/machines/start")
def start_machine_endpoint(payload: StartMachineRequest) -> dict[str, Any]:
    if not payload.device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = start_machine(device_sn=payload.device_sn.strip(), prepay_money=payload.prepay_money)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while starting machine")

    order_id = iot_result.get("order_id")
    if not order_id:
        raise HTTPException(status_code=500, detail="IoT API response missing order_id")

    return {"success": True, "order_id": order_id}


@app.get("/api/machines/{device_sn}/state")
def get_machine_state_endpoint(device_sn: str) -> dict[str, Any]:
    if not device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = get_machine_state(device_sn=device_sn.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while checking machine state")
    return {"success": True, "device_sn": device_sn.strip(), "result": iot_result}


@app.post("/api/machines/{device_sn}/create_order")
def create_order_endpoint(device_sn: str, payload: CreateOrderRequest) -> dict[str, Any]:
    if not device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = create_machine_order(device_sn=device_sn.strip(), prepay_money=payload.prepay_money)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while creating order")

    order_id = iot_result.get("order_id")
    if not order_id:
        raise HTTPException(status_code=500, detail="IoT API response missing order_id")
    return {"success": True, "device_sn": device_sn.strip(), "order_id": order_id, "result": iot_result}


@app.post("/api/machines/{device_sn}/close_order")
def close_order_endpoint(device_sn: str, payload: CloseOrderRequest) -> dict[str, Any]:
    if not device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = close_machine_order(device_sn=device_sn.strip(), order_id=payload.order_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while closing order")
    return {
        "success": True,
        "device_sn": device_sn.strip(),
        "order_id": payload.order_id.strip() if payload.order_id else None,
        "result": iot_result,
    }


@app.get("/api/meta")
def api_meta() -> dict[str, Any]:
    """Describe query params for dashboard builders."""
    return {
        "version": "1.3.0",
        "timezones": {
            "received_at": "Asia/Jerusalem (ISO local offset changes with DST)",
            "received_at_utc": "UTC — use for since= / filters against DB (stored UTC)",
        },
        "identifiers": {
            "row_id": "Our DB primary key — use in GET /api/transactions/{row_id}",
            "nayax_transaction_id": "Nayax TransactionId (same family as JSON TransactionId / Data['Transaction ID'])",
            "remote_start_transaction_id": "Nayax RemoteStartTransactionId when present",
            "pay_serv_trans_id": "Payment service transaction id when present",
            "authorization_rrn": "Authorization RRN when present",
            "sqs_message_id": "Last SQS MessageId that delivered this row (audit)",
        },
        "transaction_scalar_fields": TRANSACTION_FIELD_KEYS,
        "nayax_extra_fields": (
            "Any column Nayax sends that is not extracted to SQL still exists inside "
            "payload_json / payload (use include_payload=true, optionally parse_payload=true). "
            "Product lines are in products[] when include_products=true or on detail routes."
        ),
        "endpoints": {
            "list": "GET /api/transactions",
            "detail_by_row_id": "GET /api/transactions/{row_id}",
            "detail_by_nayax_id": "GET /api/transactions/by-nayax/{nayax_transaction_id}",
            "stats": "GET /api/stats/summary",
        },
        "list_query_params": {
            "from_date": "YYYY-MM-DD or ISO8601 — filter received_at >= (UTC)",
            "to_date": "YYYY-MM-DD or ISO8601 — filter received_at <= end of day (UTC)",
            "since": "ISO8601 UTC (or offset) — DB compare; use received_at_utc from last response",
            "site_id": "integer",
            "machine_id": "integer",
            "nayax_transaction_id": "integer",
            "limit": "1–500 default 100",
            "offset": "pagination",
            "order": "desc | asc by received_at",
            "include_payload": "include full payload_json on each row (heavy)",
            "parse_payload": "if include_payload, return payload as JSON object under key payload",
            "include_products": "include product lines (heavy)",
        },
        "live_polling_hint": "Store max(received_at_utc); next call since=<that value>&order=asc (UTC matches DB)",
    }


@app.get("/api/transactions")
def list_transactions(
    db: Session = Depends(get_db),
    from_date: Optional[str] = Query(None, description="received_at >= (YYYY-MM-DD or ISO8601 UTC)"),
    to_date: Optional[str] = Query(None, description="received_at <= end of to_date (UTC)"),
    since: Optional[str] = Query(
        None,
        description="received_at > since — UTC/offset ISO; use received_at_utc from last response for live feed",
    ),
    site_id: Optional[int] = None,
    machine_id: Optional[int] = None,
    nayax_transaction_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    include_payload: bool = False,
    parse_payload: bool = False,
    include_products: bool = False,
) -> dict[str, Any]:
    cond = _filter_conditions(
        from_date=from_date,
        to_date=to_date,
        since=since,
        site_id=site_id,
        machine_id=machine_id,
        nayax_transaction_id=nayax_transaction_id,
    )
    order_col = NayaxTransaction.received_at
    order_fn = desc if order == "desc" else asc

    base = select(NayaxTransaction)
    if include_products:
        base = base.options(selectinload(NayaxTransaction.products))
    if cond:
        base = base.where(and_(*cond))
    base = base.order_by(order_fn(order_col)).offset(offset).limit(limit)

    rows = list(db.scalars(base).all())

    count_q = select(func.count()).select_from(NayaxTransaction)
    if cond:
        count_q = count_q.where(and_(*cond))
    total = int(db.scalar(count_q) or 0)

    items: list[dict[str, Any]] = []
    for r in rows:
        item = _tx_full(
            r,
            include_payload=include_payload,
            parse_payload=parse_payload and include_payload,
        )
        if include_products:
            prods = sorted(r.products, key=lambda p: p.line_index)
            item["products"] = [_product_line(p) for p in prods]
        items.append(item)

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "filters": {
            "from_date": from_date,
            "to_date": to_date,
            "since": since,
            "site_id": site_id,
            "machine_id": machine_id,
            "nayax_transaction_id": nayax_transaction_id,
            "order": order,
        },
    }


@app.get("/api/transactions/by-nayax/{nayax_tid}")
def get_transaction_by_nayax_id(
    nayax_tid: int,
    db: Session = Depends(get_db),
    parse_payload: bool = Query(True),
) -> dict[str, Any]:
    row = db.scalar(
        select(NayaxTransaction)
        .options(selectinload(NayaxTransaction.products))
        .where(NayaxTransaction.nayax_transaction_id == nayax_tid)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    products = sorted(row.products, key=lambda p: p.line_index)
    out = _tx_full(row, include_payload=True, parse_payload=parse_payload)
    out["products"] = [_product_line(p) for p in products]
    return out


@app.get("/api/transactions/{row_id}")
def get_transaction(
    row_id: int,
    db: Session = Depends(get_db),
    parse_payload: bool = Query(True),
) -> dict[str, Any]:
    row = db.scalar(
        select(NayaxTransaction)
        .options(selectinload(NayaxTransaction.products))
        .where(NayaxTransaction.id == row_id)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Not found")
    products = sorted(row.products, key=lambda p: p.line_index)
    out = _tx_full(row, include_payload=True, parse_payload=parse_payload)
    out["products"] = [_product_line(p) for p in products]
    return out


@app.get("/api/stats/summary")
def stats_summary(
    db: Session = Depends(get_db),
    from_date: Optional[str] = Query(None),
    to_date: Optional[str] = Query(None),
    site_id: Optional[int] = None,
    machine_id: Optional[int] = None,
) -> dict[str, Any]:
    cond = _filter_conditions(
        from_date=from_date,
        to_date=to_date,
        since=None,
        site_id=site_id,
        machine_id=machine_id,
        nayax_transaction_id=None,
    )
    q = (
        select(
            NayaxTransaction.currency,
            func.count().label("count"),
            func.coalesce(func.sum(NayaxTransaction.se_value), 0).label("total_se_value"),
            func.coalesce(func.sum(NayaxTransaction.payed_value), 0).label("total_payed_value"),
        )
        .group_by(NayaxTransaction.currency)
    )
    if cond:
        q = q.where(and_(*cond))
    per_currency: list[dict[str, Any]] = []
    for cur, cnt, tse, tpy in db.execute(q).all():
        per_currency.append(
            {
                "currency": cur,
                "count": int(cnt),
                "total_se_value": float(tse) if tse is not None else 0.0,
                "total_payed_value": float(tpy) if tpy is not None else 0.0,
            }
        )
    count_q = select(func.count()).select_from(NayaxTransaction)
    if cond:
        count_q = count_q.where(and_(*cond))
    total_rows = int(db.scalar(count_q) or 0)
    return {
        "total_transactions": total_rows,
        "by_currency": per_currency,
        "filters": {"from_date": from_date, "to_date": to_date, "site_id": site_id, "machine_id": machine_id},
    }
