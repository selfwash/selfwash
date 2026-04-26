"""IoT service module."""

import base64
import json
import hashlib
import hmac
import logging
import os
import time
from email.utils import parsedate_to_datetime
from secrets import token_hex
from uuid import uuid4

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_COMMAND_PATH = "/openapi/v1/json/command"
DEFAULT_BASE_URL = "http://101.132.171.125:8686"
DEFAULT_VMT_APP_KEY = "rsaO2oAK2I7lfauO8wK3opgGnaNwiVHy"
DEFAULT_VMT_REGION = "ap-southeast-3"
OPEN_TYPE_LABELS = {
    "0": "coin",
    "1": "paper",
    "2": "card",
    "3": "network",
    "4": "nayax",
    "5": "pulse-coin",
    "6": "test_button",
}
CLOSE_TYPE_LABELS = {
    "1": "button",
    "2": "no_balance",
    "3": "idle_time_over",
    "4": "time_over",
    "5": "error",
    "6": "network",
}
logger = logging.getLogger(__name__)


def _generate_order_id() -> str:
    """Generate a reasonably unique order ID."""
    return f"ord-{int(time.time() * 1000)}-{uuid4().hex[:12]}"


def _sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _normalize_aes256_key(key_material: bytes) -> bytes:
    """
    Normalize any bytes to exactly 32 bytes for AES-256.
    - 32 bytes: use as-is
    - shorter: right-pad with zero bytes
    - longer: SHA-256 digest
    """
    if len(key_material) == 32:
        return key_material
    if len(key_material) < 32:
        return key_material.ljust(32, b"\0")
    return hashlib.sha256(key_material).digest()


def _is_crypto_debug_enabled() -> bool:
    raw = os.getenv("VMT_DEBUG_CRYPTO", "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _now_ts() -> str:
    """Current UNIX timestamp in seconds (VMT expects seconds)."""
    return str(int(time.time()))


def _decode_b64_maybe(value: str, *, urlsafe: bool) -> bytes | None:
    """
    Try base64 decode with automatic '=' padding. Returns None on failure.
    """
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(padded.encode("utf-8"))
        return base64.b64decode(padded.encode("utf-8"), validate=True)
    except Exception:
        return None


def _load_enc_key() -> bytes:
    """
    Load 32-byte encryption key from env var IOT_ENC_KEY.

    Accepted input formats:
    - raw string
    - hex-encoded string
    - base64 / base64url string

    If decoded key is not 32 bytes, normalize it:
    - shorter -> zero-pad to 32 bytes
    - longer -> SHA-256 to 32 bytes
    """
    key_source = "VMT_ENC_KEY"
    key_raw = os.getenv("VMT_ENC_KEY", "").strip()
    if not key_raw:
        key_source = "IOT_ENC_KEY"
        key_raw = os.getenv("IOT_ENC_KEY", "").strip()
    if not key_raw:
        raise ValueError("Missing VMT_ENC_KEY in environment.")

    debug = _is_crypto_debug_enabled()
    candidates: list[tuple[str, bytes]] = []

    # 1) Try hex decode first when the string looks hex-ish.
    if len(key_raw) % 2 == 0:
        try:
            hex_bytes = bytes.fromhex(key_raw)
            candidates.append(("hex", hex_bytes))
        except ValueError:
            pass

    # 2) Try standard base64.
    b64_decoded = _decode_b64_maybe(key_raw, urlsafe=False)
    if b64_decoded is not None:
        candidates.append(("base64", b64_decoded))

    # 3) Try URL-safe base64.
    b64url_decoded = _decode_b64_maybe(key_raw, urlsafe=True)
    if b64url_decoded is not None:
        candidates.append(("base64url", b64url_decoded))

    # 4) Raw bytes candidate.
    raw_bytes = key_raw.encode("utf-8")
    candidates.append(("raw", raw_bytes))

    # Prefer exact AES-256 key lengths to avoid accidental format mismatch.
    for fmt, key_bytes in candidates:
        if len(key_bytes) == 32:
            if debug:
                logger.warning(
                    "VMT crypto key loaded: source=%s format=%s raw_len=%d decoded_len=%d normalized=no",
                    key_source,
                    fmt,
                    len(key_raw),
                    len(key_bytes),
                )
            return key_bytes

    # Fallback: normalize raw bytes to 32. Useful only when env value is not in a valid 32-byte form.
    normalized = _normalize_aes256_key(raw_bytes)
    if debug:
        lengths = ", ".join([f"{fmt}:{len(value)}" for fmt, value in candidates])
        logger.warning(
            "VMT crypto key normalized fallback used: source=%s raw_len=%d candidate_lengths=[%s] normalized_len=%d",
            key_source,
            len(key_raw),
            lengths,
            len(normalized),
        )
    return normalized


def _encrypt_enc1(inner_payload: dict, kid: str, ts: str) -> str:
    """
    Encrypt inner payload with AES-256-GCM and return ENC1 JSON string.
    """
    key = _load_enc_key()
    aesgcm = AESGCM(key)

    iv = os.urandom(12)
    body_nonce = token_hex(16)
    plaintext = json.dumps(inner_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    outer = {
        "ver": "ENC1",
        "alg": "AES-256-GCM",
        "kid": kid,
        "ts": ts,
        "nonce": body_nonce,
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    }
    return json.dumps(outer, separators=(",", ":"), ensure_ascii=False)


def _decrypt_enc1_response(payload: dict) -> dict:
    """
    Decrypt ENC1 response envelope into readable JSON.

    If payload is not ENC1, returns as-is.
    """
    if payload.get("ver") != "ENC1":
        return payload

    key = _load_enc_key()
    aesgcm = AESGCM(key)

    try:
        iv = base64.b64decode(payload["iv"])
        ct = base64.b64decode(payload["ct"])
        tag = base64.b64decode(payload["tag"])
    except KeyError as exc:
        raise ValueError(f"ENC1 response missing field: {exc.args[0]}") from exc
    except Exception as exc:
        raise ValueError("Invalid base64 in ENC1 response fields") from exc

    try:
        plaintext = aesgcm.decrypt(iv, ct + tag, None)
    except Exception as exc:
        raise ValueError("Failed to decrypt ENC1 response") from exc

    try:
        decoded = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Decrypted ENC1 response is not valid JSON") from exc

    if not isinstance(decoded, dict):
        return {"data": decoded}
    return _decode_vmt_response_fields(decoded)


def _decode_vmt_response_fields(decoded: dict) -> dict:
    """
    Decode known VMT fields into readable labels based on Command_explain.jsonc.
    """
    data = decoded.get("data")
    if not isinstance(data, dict):
        return decoded

    order_info = data.get("order_info")
    if not isinstance(order_info, dict):
        return decoded

    open_type_raw = order_info.get("open_type")
    close_type_raw = order_info.get("close_type")

    if open_type_raw is not None:
        open_key = str(open_type_raw).strip()
        open_label = OPEN_TYPE_LABELS.get(open_key)
        if open_label:
            order_info["open_type_label"] = open_label

    if close_type_raw not in (None, ""):
        close_key = str(close_type_raw).strip()
        close_label = CLOSE_TYPE_LABELS.get(close_key)
        if close_label:
            order_info["close_type_label"] = close_label

    return decoded


def _is_timestamp_expired(payload: dict) -> bool:
    """Detect VMT timestamp expiry error from response payload."""
    if not isinstance(payload, dict):
        return False
    response = payload.get("response")
    if not isinstance(response, dict):
        return False
    errors = response.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, str) and "timestamp expired" in item.lower():
                return True
    message = response.get("message")
    if isinstance(message, str) and "timestamp expired" in message.lower():
        return True
    return False


def _server_time_from_response(response: requests.Response) -> int | None:
    """Extract server clock (seconds) from HTTP Date response header."""
    date_header = response.headers.get("Date", "").strip()
    if not date_header:
        return None
    try:
        dt = parsedate_to_datetime(date_header)
        return int(dt.timestamp())
    except Exception:
        return None


def _build_signature(
    app_secret: str,
    app_key: str,
    timestamp: str,
    nonce: str,
    enc1_json_body: str,
) -> str:
    command_path = os.getenv("VMT_COMMAND_PATH", "").strip() or os.getenv("IOT_COMMAND_PATH", "").strip() or DEFAULT_COMMAND_PATH
    body_hash = _sha256_hex(enc1_json_body.encode("utf-8"))
    string_to_sign = "\n".join(
        [
            "POST",
            command_path,
            app_key,
            timestamp,
            nonce,
            body_hash,
        ]
    )
    return hmac.new(
        app_secret.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _send_command(device_sn: str, method: str, params: dict) -> dict:
    app_key = os.getenv("VMT_APP_KEY", "").strip() or os.getenv("IOT_APP_KEY", "").strip() or DEFAULT_VMT_APP_KEY
    app_secret = os.getenv("VMT_APP_SECRET", "").strip() or os.getenv("IOT_APP_SECRET", "").strip()
    kid = os.getenv("VMT_ENC_KID", "").strip() or os.getenv("IOT_ENC_KID", "enc-18").strip()
    region = os.getenv("VMT_REGION", "").strip() or DEFAULT_VMT_REGION
    base_url = (os.getenv("VMT_BASE_URL", "").strip() or os.getenv("IOT_BASE_URL", DEFAULT_BASE_URL).strip()).rstrip("/")
    command_path = os.getenv("VMT_COMMAND_PATH", "").strip() or os.getenv("IOT_COMMAND_PATH", "").strip() or DEFAULT_COMMAND_PATH

    if not app_key:
        raise ValueError("Missing VMT_APP_KEY in environment.")
    if not app_secret:
        raise ValueError("Missing VMT_APP_SECRET in environment.")
    if not device_sn:
        raise ValueError("device_sn is required.")
    if not method:
        raise ValueError("method is required.")

    inner_payload = {
        "version": "V26.0",
        "device_sn": device_sn,
        "method": method,
        "params": params,
    }

    url = f"{base_url}{command_path}"
    debug = _is_crypto_debug_enabled()

    def _send_once(ts: str) -> tuple[dict, requests.Response]:
        enc1_json_body = _encrypt_enc1(inner_payload, kid=kid, ts=ts)
        request_nonce = token_hex(16)
        signature = _build_signature(
            app_secret=app_secret,
            app_key=app_key,
            timestamp=ts,
            nonce=request_nonce,
            enc1_json_body=enc1_json_body,
        )
        headers = {
            "X-App-Key": app_key,
            "X-Timestamp": ts,
            "X-Nonce": request_nonce,
            "X-Signature": signature,
            "X-Region": region,
            "Content-Type": "application/json",
        }
        response = requests.post(url, data=enc1_json_body, headers=headers, timeout=15)
        response.raise_for_status()
        try:
            raw_payload = response.json()
        except ValueError:
            raw_payload = {"status_code": response.status_code, "raw": response.text}
        return _decrypt_enc1_response(raw_payload), response

    first_ts = _now_ts()
    payload, response = _send_once(first_ts)

    if _is_timestamp_expired(payload):
        server_ts = _server_time_from_response(response)
        if server_ts is not None:
            retry_ts = str(server_ts + 1)
            if debug:
                logger.warning(
                    "VMT timestamp retry: first_ts=%s server_ts=%d retry_ts=%s",
                    first_ts,
                    server_ts,
                    retry_ts,
                )
        else:
            retry_ts = _now_ts()
            if debug:
                logger.warning("VMT timestamp retry: first_ts=%s no_server_date retry_ts=%s", first_ts, retry_ts)

        payload, _ = _send_once(retry_ts)

    return payload


def start_machine(device_sn: str, prepay_money: float) -> dict:
    """
    Call IoT command API to start a car wash machine.
    """
    order_id = _generate_order_id()
    payload = _send_command(
        device_sn=device_sn,
        method="create_order",
        params={
            "order_id": order_id,
            "prepay_money": prepay_money,
        },
    )
    payload["order_id"] = order_id
    return payload


def get_machine_state(device_sn: str) -> dict:
    """Call IoT command API to fetch machine state."""
    return _send_command(device_sn=device_sn, method="query_state", params={})


def create_machine_order(device_sn: str, prepay_money: float) -> dict:
    """Call IoT command API to create an order on a machine."""
    return start_machine(device_sn=device_sn, prepay_money=prepay_money)


def close_machine_order(device_sn: str, order_id: str) -> dict:
    """Call IoT command API to close an existing order."""
    if not order_id or not order_id.strip():
        raise ValueError("order_id is required.")
    return _send_command(
        device_sn=device_sn,
        method="close_order",
        params={"order_id": order_id.strip()},
    )
