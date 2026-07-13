"""
Read-only HTTP API for Lovable / dashboards. Uses the same db engine as consumer.py. Railway: DATABASE_URL must reference PostgreSQL (persistent).
"""

from __future__ import annotations

import json
import logging
import os
import re
import base64
import threading
import time as time_module
from datetime import datetime, time, timezone
from decimal import Decimal
from typing import Any, Literal, Optional
from zoneinfo import ZoneInfo

import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from requests import RequestException
from sqlalchemy import and_, asc, delete, desc, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

load_dotenv()

from db import (
    AppUser,
    AppUserPermission,
    MachineState,
    NayaxTransaction,
    NayaxTransactionProduct,
    SessionLocal,
    init_db,
)
from iot_service import (
    _decrypt_enc1_response,
    _extract_query_state,
    close_machine_order,
    create_machine_order,
    get_machine_state,
    list_machine_device_sns,
    read_machine_config,
    start_machine,
    write_machine_config,
)
from security import (
    ALL_KNOWN_PERMISSIONS,
    AuthContext,
    PERM_ADMIN_USERS,
    PERM_MACHINES_READ,
    PERM_MACHINES_WRITE,
    PERM_NAYAX_READ,
    REVIEW_APPROVED,
    REVIEW_PENDING,
    REVIEW_REJECTED,
    create_access_token,
    decode_access_token,
    hash_password,
    load_permissions_for_user,
    verify_password,
)

READ_API_KEY = os.environ.get("READ_API_KEY", "").strip()
logger = logging.getLogger(__name__)
JWT_SECRET = os.environ.get("JWT_SECRET", "").strip()
SIGNUP_NOTIFY_WEBHOOK_URL = os.environ.get("SIGNUP_NOTIFY_WEBHOOK_URL", "").strip()
SIGNUP_NOTIFY_WEBHOOK_SECRET = os.environ.get("SIGNUP_NOTIFY_WEBHOOK_SECRET", "").strip()
_ALLOW_SIGNUP_RAW = os.environ.get("ALLOW_PUBLIC_SIGNUP", "1").strip().lower()
ALLOW_PUBLIC_SIGNUP = _ALLOW_SIGNUP_RAW not in ("0", "false", "no", "")
VMT_CALLBACK_TOKEN = os.environ.get("VMT_CALLBACK_TOKEN", "").strip()

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


def _log_iot_request_exception(exc: RequestException, *, context: str) -> None:
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    response_body = getattr(response, "text", "")
    logger.exception(
        "IoT API request failed (%s). status_code=%s response=%s error=%s",
        context,
        status_code,
        response_body[:1000],
        str(exc),
    )


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


def _cors_config() -> dict[str, Any]:
    """
    CORS: default * for dev. In production, CORS_ORIGINS is a comma list.
    Lovable **preview** uses e.g. https://xxxx.lovableproject.com (not only *.lovable.app);
    we allow that via allow_origin_regex when CORS_LOVABLE_REGEX=1 (default on).
    """
    raw = os.environ.get("CORS_ORIGINS", "*").strip()
    lovable_re = None
    if os.environ.get("CORS_LOVABLE_REGEX", "1").lower() in ("1", "true", "yes"):
        # Lovable preview + app hosting subdomains
        lovable_re = r"^https://[a-zA-Z0-9.\-]+\.(lovableproject\.com|lovable\.app)$"
    if raw == "*":
        return {
            "allow_origins": ["*"],
            "allow_origin_regex": None,
            "allow_credentials": False,
        }
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    lovable_origin = os.environ.get("LOVABLE_ORIGIN", "").strip()
    if lovable_origin:
        origins.append(lovable_origin)
    lovable_origins_raw = os.environ.get("LOVABLE_ORIGINS", "").strip()
    if lovable_origins_raw:
        origins.extend([o.strip() for o in lovable_origins_raw.split(",") if o.strip()])

    origins = list(dict.fromkeys(origins))
    return {
        "allow_origins": origins,
        "allow_origin_regex": lovable_re,
        "allow_credentials": True,
    }


_cors = _cors_config()
# Used when CORSMiddleware does not add headers on some 5xx paths (browsers then report a CORS error).
_CORS_STRICT_EXACT: list[str] = list(_cors.get("allow_origins") or [])
_CORS_STRICT_RE: str | None = _cors.get("allow_origin_regex")
_CORS_STRICT_CREDS: bool = bool(_cors.get("allow_credentials"))


def _origin_allowed_for_cors(request_origin: str) -> bool:
    if not request_origin:
        return False
    if _CORS_STRICT_EXACT == ["*"]:
        return True
    if request_origin in _CORS_STRICT_EXACT:
        return True
    if _CORS_STRICT_RE and re.fullmatch(_CORS_STRICT_RE, request_origin):
        return True
    return False


class _CorsMissingHeaderPatch(BaseHTTPMiddleware):
    """If response has no Access-Control-Allow-Origin, set it for allowed Lovable / CORS_ORIGINS (fixes browser CORS on 5xx)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        origin = request.headers.get("origin")
        if not origin or response.headers.get("access-control-allow-origin"):
            return response
        if not _origin_allowed_for_cors(origin):
            return response
        if _CORS_STRICT_EXACT == ["*"]:
            response.headers["Access-Control-Allow-Origin"] = "*"
        else:
            response.headers["Access-Control-Allow-Origin"] = origin
            if "vary" not in {k.lower() for k in response.headers}:
                response.headers["Vary"] = "Origin"
            if _CORS_STRICT_CREDS:
                response.headers["Access-Control-Allow-Credentials"] = "true"
        return response


app = FastAPI(title="SelfWash API", version="1.4.1")
_cors_mw: dict[str, Any] = {
    "allow_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["*"],
    **_cors,
}
if _cors_mw.get("allow_origin_regex") is None:
    _cors_mw.pop("allow_origin_regex", None)
app.add_middleware(CORSMiddleware, **_cors_mw)
app.add_middleware(_CorsMissingHeaderPatch)


def get_db() -> Any:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _raise_if_user_not_approved_for_api(user: AppUser) -> None:
    """Block JWT access for pending/rejected accounts (distinct from is_active for approved users)."""
    if user.review_status == REVIEW_PENDING:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "pending_approval", "message": "Account is waiting for admin approval."},
        )
    if user.review_status == REVIEW_REJECTED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "rejected", "message": "This account was not approved."},
        )


def _notify_signup_webhook(
    *,
    user_id: int,
    username: str,
    email: Optional[str],
    note: Optional[str],
) -> None:
    if not SIGNUP_NOTIFY_WEBHOOK_URL:
        return
    body: dict[str, Any] = {
        "event": "user_signup_pending",
        "user_id": user_id,
        "username": username,
        "email": email,
        "registration_note": note,
    }
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if SIGNUP_NOTIFY_WEBHOOK_SECRET:
        headers["X-Webhook-Secret"] = SIGNUP_NOTIFY_WEBHOOK_SECRET
    try:
        r = requests.post(SIGNUP_NOTIFY_WEBHOOK_URL, json=body, headers=headers, timeout=12)
        if r.status_code >= 400:
            logger.warning("Signup notify webhook returned %s: %s", r.status_code, r.text[:500])
    except RequestException as exc:
        logger.warning("Signup notify webhook request failed: %s", exc)


def authenticate(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Valid `X-API-Key` (when READ_API_KEY is set) grants full access; otherwise use `Authorization: Bearer <JWT>`."""
    if READ_API_KEY and x_api_key == READ_API_KEY:
        return AuthContext(source="api_key", permissions=set(ALL_KNOWN_PERMISSIONS))
    if authorization and authorization.startswith("Bearer "):
        if not JWT_SECRET:
            raise HTTPException(status_code=503, detail="JWT auth not configured (set JWT_SECRET)")
        token = authorization[7:].strip()
        try:
            payload = decode_access_token(token)
            uid = int(payload["sub"])
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        user = db.get(AppUser, uid)
        if not user:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        _raise_if_user_not_approved_for_api(user)
        if not user.is_active:
            raise HTTPException(status_code=401, detail="User inactive or not found")
        perms = load_permissions_for_user(db, user)
        return AuthContext(source="jwt", user=user, permissions=perms)
    if READ_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key or Bearer token")
    raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token> (set READ_API_KEY for key-based access)")


def require_permission(perm: str):
    def _check(auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if not auth.has(perm):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {perm}")
        return auth

    return _check


def _maybe_bootstrap_admin() -> None:
    user = os.environ.get("BOOTSTRAP_ADMIN_USERNAME", "").strip()
    pw = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "").strip()
    if not user or not pw:
        return
    db = SessionLocal()
    try:
        n = db.scalar(select(func.count()).select_from(AppUser))
        if n and n > 0:
            return
        db.add(
            AppUser(
                username=user,
                password_hash=hash_password(pw),
                is_active=True,
                is_superuser=True,
                review_status=REVIEW_APPROVED,
            )
        )
        db.commit()
        logger.info("Bootstrap: created superuser %s", user)
    except Exception:
        logger.exception("Bootstrap admin failed")
        db.rollback()
    finally:
        db.close()


@app.on_event("startup")
def _startup() -> None:
    init_db()
    _maybe_bootstrap_admin()
    if not JWT_SECRET:
        logger.warning(
            "JWT_SECRET is not set: POST /api/auth/login and Bearer auth will return 503. "
            "Set JWT_SECRET in Railway (Variables)."
        )
    _start_machine_state_poller()


@app.on_event("shutdown")
def _shutdown() -> None:
    _machine_state_poll_stop.set()


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


def _pick_str_any(payload: dict[str, Any], keys: list[str]) -> Optional[str]:
    for k in keys:
        v = payload.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    nested = payload.get("Data")
    if isinstance(nested, dict):
        for k in keys:
            v = nested.get(k)
            if v is not None and str(v).strip():
                return str(v).strip()
    return None


def _extract_callback_event_time(payload: dict[str, Any]) -> Optional[datetime]:
    raw = _pick_str_any(payload, ["event_time", "timestamp", "time", "machine_time", "MachineTime"])
    if raw:
        try:
            return _parse_instant(raw)
        except Exception:
            return None
    return None


def _extract_callback_state(payload: dict[str, Any]) -> Optional[str]:
    state = _pick_str_any(payload, ["state", "machine_state", "MachineState", "status", "Status"])
    if state:
        return state
    data = payload.get("data")
    if isinstance(data, dict):
        ds = data.get("device_state")
        if isinstance(ds, dict):
            nested = ds.get("state")
            if nested is not None and str(nested).strip():
                return str(nested).strip()
        order_info = data.get("order_info")
        if isinstance(order_info, dict):
            # order_update without explicit state means an active order in progress.
            remain = order_info.get("operation_remain_time")
            if remain is not None and str(remain).strip() not in ("", "0"):
                return "busy"
    event_name = _pick_str_any(payload, ["event", "event_type"])
    if event_name:
        ev = event_name.strip().lower()
        if ev in ("order_create", "order_update"):
            return "busy"
        if ev == "order_close":
            return "idle"
    return None


def _normalize_callback_payload(decoded_payload: dict[str, Any]) -> dict[str, Any]:
    """
    VMT callback ENC1 may arrive in nested wrappers, e.g.:
    {"data":"{\"body_b64\":\"...\"}"} or {"body_b64":"..."}.
    Try a few safe unwrap passes until business JSON dict is reached.
    """
    current: Any = decoded_payload
    for _ in range(4):
        if not isinstance(current, dict):
            break
        if isinstance(current.get("body_b64"), str):
            try:
                raw = base64.b64decode(current["body_b64"]).decode("utf-8")
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    current = parsed
                    continue
            except Exception:
                break
        data_field = current.get("data")
        if isinstance(data_field, str):
            try:
                parsed = json.loads(data_field)
                if isinstance(parsed, dict):
                    current = parsed
                    continue
            except Exception:
                pass
        break
    if isinstance(current, dict):
        return current
    return decoded_payload


def _save_machine_state_snapshot(
    db: Session,
    *,
    device_sn: str,
    state: Optional[str],
    payload: dict[str, Any],
    source_event_time: Optional[datetime] = None,
) -> MachineState:
    """Upsert current state for device_sn (one row per machine, no history)."""
    now = datetime.now(timezone.utc)
    payload_json = json.dumps(payload, ensure_ascii=False)
    row = db.scalar(select(MachineState).where(MachineState.device_sn == device_sn))
    if row is None:
        row = MachineState(
            device_sn=device_sn,
            state=state,
            source_event_time=source_event_time,
            payload_json=payload_json,
            created_at=now,
        )
        db.add(row)
    else:
        row.state = state
        row.source_event_time = source_event_time
        row.payload_json = payload_json
        row.created_at = now
    db.commit()
    db.refresh(row)
    return row


def _extract_device_sns_from_list_payload(payload: Any) -> list[str]:
    """Collect device_sn values from nested VMT list_device_sn response shapes."""
    found: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_l = str(key).lower()
                if key_l in ("device_sn", "devicesn", "device_sn_list", "sn") and isinstance(value, str):
                    sn = value.strip()
                    if sn:
                        found.append(sn)
                elif key_l in ("device_sn", "devicesn", "sn") and isinstance(value, (int, float)):
                    found.append(str(value))
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, str) and item.strip():
                    # list_device_sn sometimes returns a plain list of serials
                    found.append(item.strip())
                else:
                    walk(item)

    walk(payload)
    return list(dict.fromkeys(found))


def _collect_device_sns_for_poll(db: Session) -> list[str]:
    sns: list[str] = []
    try:
        iot_result = list_machine_device_sns(limit=100)
        sns.extend(_extract_device_sns_from_list_payload(iot_result))
    except Exception:
        logger.exception("Machine state poll: failed to list devices from VMT")
    try:
        sns.extend(list(db.scalars(select(MachineState.device_sn)).all()))
    except Exception:
        logger.exception("Machine state poll: failed to load device_sn from DB")
    return list(dict.fromkeys(s.strip() for s in sns if s and str(s).strip()))


def _poll_all_machine_states_once() -> None:
    """Query VMT state for every known machine and upsert into machine_states."""
    db = SessionLocal()
    try:
        device_sns = _collect_device_sns_for_poll(db)
        if not device_sns:
            logger.info("Machine state poll: no devices to query")
            return
        logger.info("Machine state poll: querying %s device(s)", len(device_sns))
        ok = 0
        for device_sn in device_sns:
            try:
                iot_result = get_machine_state(device_sn=device_sn)
                state = _extract_query_state(iot_result)
                now = datetime.now(timezone.utc)
                _save_machine_state_snapshot(
                    db,
                    device_sn=device_sn,
                    state=state,
                    payload={
                        "version": "poll",
                        "event": "query_state_poll",
                        "device_sn": device_sn,
                        "data": iot_result,
                    },
                    source_event_time=now,
                )
                ok += 1
                logger.info(
                    "Machine state poll device_sn=%s state=%s",
                    device_sn,
                    state,
                )
            except Exception:
                logger.exception("Machine state poll failed for device_sn=%s", device_sn)
            time_module.sleep(0.15)
        logger.info("Machine state poll done ok=%s/%s", ok, len(device_sns))
    finally:
        db.close()


_machine_state_poll_stop = threading.Event()
_machine_state_poll_thread: Optional[threading.Thread] = None


def _machine_state_poll_interval_sec() -> int:
    raw = os.environ.get("MACHINE_STATE_POLL_INTERVAL_SEC", "60").strip()
    try:
        return int(raw)
    except ValueError:
        return 60


def _machine_state_poll_loop() -> None:
    interval = _machine_state_poll_interval_sec()
    logger.info("Machine state poller running every %ss", interval)
    while True:
        try:
            _poll_all_machine_states_once()
        except Exception:
            logger.exception("Machine state poll cycle failed")
        if _machine_state_poll_stop.wait(timeout=interval):
            logger.info("Machine state poller stopped")
            break


def _start_machine_state_poller() -> None:
    global _machine_state_poll_thread
    interval = _machine_state_poll_interval_sec()
    if interval <= 0:
        logger.info("Machine state poller disabled (MACHINE_STATE_POLL_INTERVAL_SEC=%s)", interval)
        return
    if _machine_state_poll_thread and _machine_state_poll_thread.is_alive():
        return
    _machine_state_poll_stop.clear()
    _machine_state_poll_thread = threading.Thread(
        target=_machine_state_poll_loop,
        name="machine-state-poller",
        daemon=True,
    )
    _machine_state_poll_thread.start()


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


class WriteConfigRequest(BaseModel):
    params: dict[str, Any]


class LoginRequest(BaseModel):
    username: str
    password: str


class AdminUserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=6, max_length=256)
    is_active: bool = True
    is_superuser: bool = False
    permissions: list[str] = Field(default_factory=list)


class AdminUserUpdateRequest(BaseModel):
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    permissions: Optional[list[str]] = None


class RegisterRequest(BaseModel):
    username: str = Field(min_length=2, max_length=128)
    password: str = Field(min_length=6, max_length=256)
    email: Optional[str] = Field(default=None, max_length=256)
    registration_note: Optional[str] = Field(default=None, max_length=4000)


class UserReviewRequest(BaseModel):
    action: Literal["approve", "reject"]
    permissions: list[str] = Field(
        default_factory=list,
        description="Applied on approve; ignored for superuser (all permissions).",
    )
    is_superuser: bool = False


@app.post("/api/auth/login")
def auth_login(body: LoginRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not JWT_SECRET:
        raise HTTPException(status_code=503, detail="JWT_SECRET is not set; cannot issue tokens")
    u = db.scalar(select(AppUser).where(AppUser.username == body.username.strip()))
    if u is None or not verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if u.review_status == REVIEW_PENDING:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "pending_approval", "message": "Account is waiting for admin approval."},
        )
    if u.review_status == REVIEW_REJECTED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "rejected", "message": "This account was not approved."},
        )
    if not u.is_active:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    token = create_access_token(user_id=u.id)
    perms = load_permissions_for_user(db, u)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": u.id,
            "username": u.username,
            "is_superuser": u.is_superuser,
            "permissions": sorted(perms),
        },
    }


@app.post("/api/auth/register")
def auth_register(body: RegisterRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Request access: creates a user in pending state; admin must approve and assign permissions."""
    if not ALLOW_PUBLIC_SIGNUP:
        raise HTTPException(status_code=403, detail="Public registration is disabled")
    uname = body.username.strip()
    if not uname:
        raise HTTPException(status_code=400, detail="Username is required")
    if db.scalar(select(AppUser).where(AppUser.username == uname)) is not None:
        raise HTTPException(status_code=400, detail="Username already taken")
    email = (body.email or "").strip() or None
    note = (body.registration_note or "").strip() or None
    u = AppUser(
        username=uname,
        password_hash=hash_password(body.password),
        is_active=False,
        is_superuser=False,
        review_status=REVIEW_PENDING,
        email=email,
        registration_note=note,
    )
    try:
        db.add(u)
        db.commit()
        db.refresh(u)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("auth_register DB error")
        raise HTTPException(
            status_code=500,
            detail="Could not create account. Admin: check DB migrations, Railway logs, and app_users table.",
        ) from exc
    _notify_signup_webhook(user_id=u.id, username=uname, email=email, note=note)
    return {
        "status": "pending",
        "message": "Request received. You can sign in after an administrator approves your account.",
        "user_id": u.id,
    }


@app.get("/api/auth/me")
def auth_me(auth: AuthContext = Depends(authenticate)) -> dict[str, Any]:
    if auth.source == "api_key":
        return {"type": "api_key", "full_access": True}
    assert auth.user is not None
    u = auth.user
    return {
        "type": "user",
        "id": u.id,
        "username": u.username,
        "is_superuser": u.is_superuser,
        "permissions": sorted(auth.permissions),
        "review_status": u.review_status,
        "email": u.email,
    }


@app.get("/api/admin/permissions")
def admin_list_permissions(_auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS))) -> dict[str, Any]:
    return {"permissions": sorted(ALL_KNOWN_PERMISSIONS)}


@app.get("/api/admin/users")
def admin_list_users(db: Session = Depends(get_db), _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS))) -> dict[str, Any]:
    users = list(db.scalars(select(AppUser).order_by(AppUser.id)).all())
    out: list[dict[str, Any]] = []
    for u in users:
        perms = load_permissions_for_user(db, u) if not u.is_superuser else set(ALL_KNOWN_PERMISSIONS)
        out.append(
            {
                "id": u.id,
                "username": u.username,
                "is_active": u.is_active,
                "is_superuser": u.is_superuser,
                "review_status": u.review_status,
                "email": u.email,
                "registration_note": u.registration_note,
                "permissions": sorted(perms) if not u.is_superuser else sorted(ALL_KNOWN_PERMISSIONS),
            }
        )
    return {"items": out}


@app.get("/api/admin/pending-registrations")
def admin_list_pending(
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS)),
) -> dict[str, Any]:
    rows = list(
        db.scalars(select(AppUser).where(AppUser.review_status == REVIEW_PENDING).order_by(AppUser.created_at)).all()
    )
    items: list[dict[str, Any]] = []
    for u in rows:
        items.append(
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "registration_note": u.registration_note,
                "created_at": _iso_utc(u.created_at),
            }
        )
    return {"items": items}


@app.post("/api/admin/users/{user_id}/review")
def admin_review_user(
    user_id: int,
    body: UserReviewRequest,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS)),
) -> dict[str, Any]:
    u = db.get(AppUser, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.action == "reject":
        u.review_status = REVIEW_REJECTED
        u.is_active = False
        u.is_superuser = False
        db.execute(delete(AppUserPermission).where(AppUserPermission.user_id == u.id))
        db.commit()
        return {"status": "rejected", "user_id": u.id}
    if u.review_status == REVIEW_APPROVED and u.is_active:
        raise HTTPException(
            status_code=400,
            detail="User is already active; use PATCH /api/admin/users to update permissions or deactivate.",
        )
    bad = [p for p in body.permissions if p not in ALL_KNOWN_PERMISSIONS]
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown permissions: {bad}")
    u.review_status = REVIEW_APPROVED
    u.is_active = True
    u.is_superuser = bool(body.is_superuser)
    db.execute(delete(AppUserPermission).where(AppUserPermission.user_id == u.id))
    if u.is_superuser:
        pass
    else:
        for p in body.permissions:
            if p:
                db.add(AppUserPermission(user_id=u.id, permission=p))
    db.commit()
    return {
        "status": "approved",
        "user_id": u.id,
        "is_superuser": u.is_superuser,
        "permissions": sorted(ALL_KNOWN_PERMISSIONS) if u.is_superuser else sorted(body.permissions),
    }


@app.post("/api/admin/users")
def admin_create_user(
    body: AdminUserCreateRequest,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS)),
) -> dict[str, Any]:
    uname = body.username.strip()
    if db.scalar(select(AppUser).where(AppUser.username == uname)) is not None:
        raise HTTPException(status_code=400, detail="Username already exists")
    bad = [p for p in body.permissions if p not in ALL_KNOWN_PERMISSIONS]
    if bad:
        raise HTTPException(status_code=400, detail=f"Unknown permissions: {bad}")
    u = AppUser(
        username=uname,
        password_hash=hash_password(body.password),
        is_active=body.is_active,
        is_superuser=body.is_superuser,
        review_status=REVIEW_APPROVED,
    )
    db.add(u)
    db.flush()
    for p in body.permissions:
        if p:
            db.add(AppUserPermission(user_id=u.id, permission=p))
    db.commit()
    return {"id": u.id, "username": u.username}


@app.patch("/api/admin/users/{user_id}")
def admin_update_user(
    user_id: int,
    body: AdminUserUpdateRequest,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS)),
) -> dict[str, str]:
    u = db.get(AppUser, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    if body.password is not None:
        u.password_hash = hash_password(body.password)
    if body.is_active is not None:
        u.is_active = body.is_active
    if body.is_superuser is not None:
        u.is_superuser = body.is_superuser
    if body.permissions is not None:
        bad = [p for p in body.permissions if p not in ALL_KNOWN_PERMISSIONS]
        if bad:
            raise HTTPException(status_code=400, detail=f"Unknown permissions: {bad}")
        db.execute(delete(AppUserPermission).where(AppUserPermission.user_id == u.id))
        for p in body.permissions:
            if p:
                db.add(AppUserPermission(user_id=u.id, permission=p))
    db.commit()
    return {"status": "ok"}


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_ADMIN_USERS)),
) -> dict[str, str]:
    u = db.get(AppUser, user_id)
    if u is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(u)
    db.commit()
    return {"status": "ok"}


@app.post("/api/machines/start")
def start_machine_endpoint(
    payload: StartMachineRequest,
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_WRITE)),
) -> dict[str, Any]:
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
def get_machine_state_endpoint(
    device_sn: str,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_READ)),
) -> dict[str, Any]:
    device_sn = device_sn.strip()
    if not device_sn:
        raise HTTPException(status_code=400, detail="device_sn is required")
    row = db.scalar(select(MachineState).where(MachineState.device_sn == device_sn))
    if row is None:
        logger.info("get_machine_state device_sn=%s -> 404 no state found", device_sn)
        raise HTTPException(status_code=404, detail=f"No state found yet for machine {device_sn}")
    try:
        payload = json.loads(row.payload_json)
    except Exception:
        payload = {"raw": row.payload_json}
    state = row.state or (_extract_callback_state(payload) if isinstance(payload, dict) else None)
    response = {
        "success": True,
        "device_sn": device_sn,
        "state": state,
        "source_event_time": _iso_utc(row.source_event_time),
        "received_at": _iso_utc(row.created_at),
        "result": payload,
    }
    logger.info(
        "get_machine_state device_sn=%s response=%s",
        device_sn,
        json.dumps(response, default=str, ensure_ascii=False),
    )
    return response


@app.post("/api/machines/callback")
def machine_callback_from_vmt(
    payload: dict[str, Any],
    x_callback_token: Optional[str] = Header(None, alias="X-Callback-Token"),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    VMT webhook/callback endpoint for machine status pushes.
    Optional auth: set VMT_CALLBACK_TOKEN and send X-Callback-Token header.
    """
    if VMT_CALLBACK_TOKEN and x_callback_token != VMT_CALLBACK_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid callback token")
    decoded_payload = payload
    if payload.get("ver") == "ENC1":
        try:
            decoded_payload = _decrypt_enc1_response(payload)
            decoded_payload = _normalize_callback_payload(decoded_payload)
        except Exception as exc:
            logger.exception("Failed to decrypt ENC1 machine callback payload")
            raise HTTPException(status_code=400, detail="Invalid ENC1 callback payload") from exc
    device_sn = _pick_str_any(decoded_payload, ["device_sn", "deviceSN", "DeviceSn", "DeviceSN", "sn", "SN"])
    if not device_sn:
        raise HTTPException(status_code=400, detail="Callback payload missing device_sn")
    state = _extract_callback_state(decoded_payload)
    source_event_time = _extract_callback_event_time(decoded_payload)
    row = _save_machine_state_snapshot(
        db,
        device_sn=device_sn,
        state=state,
        payload=decoded_payload,
        source_event_time=source_event_time,
    )
    return {
        "ok": True,
        "machine_state_id": row.id,
        "device_sn": device_sn,
    }


@app.get("/api/machines/list")
def list_machines_endpoint(
    limit: int = Query(100, ge=1, le=100),
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_READ)),
) -> dict[str, Any]:
    try:
        iot_result = list_machine_device_sns(limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while listing machines")
    return {"success": True, "result": iot_result}


@app.get("/api/machines/{device_sn}/config")
def get_machine_config_endpoint(
    device_sn: str,
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_READ)),
) -> dict[str, Any]:
    if not device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = read_machine_config(device_sn=device_sn.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException as exc:
        _log_iot_request_exception(exc, context=f"read_config device_sn={device_sn.strip()}")
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while reading config")
    return {"success": True, "device_sn": device_sn.strip(), "result": iot_result}


@app.post("/api/machines/{device_sn}/config")
def write_machine_config_endpoint(
    device_sn: str,
    payload: WriteConfigRequest,
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_WRITE)),
) -> dict[str, Any]:
    if not device_sn.strip():
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = write_machine_config(device_sn=device_sn.strip(), params=payload.params)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while writing config")
    return {"success": True, "device_sn": device_sn.strip(), "result": iot_result}


@app.post("/api/machines/{device_sn}/create_order")
def create_order_endpoint(
    device_sn: str,
    payload: CreateOrderRequest,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_WRITE)),
) -> dict[str, Any]:
    device_sn = device_sn.strip()
    if not device_sn:
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = create_machine_order(device_sn=device_sn, prepay_money=payload.prepay_money)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException as exc:
        _log_iot_request_exception(
            exc,
            context=f"create_order device_sn={device_sn} prepay_money={payload.prepay_money}",
        )
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        logger.exception(
            "Unexpected server error while creating order. device_sn=%s prepay_money=%s",
            device_sn,
            payload.prepay_money,
        )
        raise HTTPException(status_code=500, detail="Unexpected server error while creating order")

    order_id = iot_result.get("order_id")
    if not order_id:
        logger.error(
            "IoT API response missing order_id. device_sn=%s prepay_money=%s iot_result=%s",
            device_sn,
            payload.prepay_money,
            str(iot_result)[:2000],
        )
        raise HTTPException(status_code=500, detail="IoT API response missing order_id")
    # Write-through state update so UI can reflect "busy" immediately even before callback arrives.
    _save_machine_state_snapshot(
        db,
        device_sn=device_sn,
        state="busy",
        payload={
            "version": "local",
            "event": "create_order_ack",
            "device_sn": device_sn,
            "data": {
                "order_info": {"order_id": order_id, "prepay_money": payload.prepay_money},
                "iot_result": iot_result,
            },
        },
    )
    return {"success": True, "device_sn": device_sn, "order_id": order_id, "result": iot_result}


@app.post("/api/machines/{device_sn}/close_order")
def close_order_endpoint(
    device_sn: str,
    payload: CloseOrderRequest,
    db: Session = Depends(get_db),
    _auth: AuthContext = Depends(require_permission(PERM_MACHINES_WRITE)),
) -> dict[str, Any]:
    device_sn = device_sn.strip()
    if not device_sn:
        raise HTTPException(status_code=400, detail="device_sn is required")
    try:
        iot_result = close_machine_order(device_sn=device_sn, order_id=payload.order_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RequestException:
        raise HTTPException(status_code=500, detail="Failed to call IoT command API")
    except Exception:
        raise HTTPException(status_code=500, detail="Unexpected server error while closing order")
    # Write-through optimistic close so UI does not wait for delayed callback.
    _save_machine_state_snapshot(
        db,
        device_sn=device_sn,
        state="idle",
        payload={
            "version": "local",
            "event": "close_order_ack",
            "device_sn": device_sn,
            "data": {
                "order_info": {"order_id": payload.order_id.strip() if payload.order_id else None},
                "iot_result": iot_result,
            },
        },
    )
    return {
        "success": True,
        "device_sn": device_sn,
        "order_id": payload.order_id.strip() if payload.order_id else None,
        "result": iot_result,
    }


@app.get("/api/meta")
def api_meta(_auth: AuthContext = Depends(require_permission(PERM_NAYAX_READ))) -> dict[str, Any]:
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
    _auth: AuthContext = Depends(require_permission(PERM_NAYAX_READ)),
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
    _auth: AuthContext = Depends(require_permission(PERM_NAYAX_READ)),
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
    _auth: AuthContext = Depends(require_permission(PERM_NAYAX_READ)),
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
    _auth: AuthContext = Depends(require_permission(PERM_NAYAX_READ)),
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
