"""IoT service module."""

import base64
import json
import hashlib
import hmac
import os
import time
from secrets import token_hex
from uuid import uuid4

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_COMMAND_PATH = "/openapi/v1/json/command"
DEFAULT_BASE_URL = "http://101.132.171.125:8686"
DEFAULT_VMT_APP_KEY = "rsaO2oAK2I7lfauO8wK3opgGnaNwiVHy"
DEFAULT_VMT_REGION = "ap-southeast-3"


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
    key_raw = os.getenv("VMT_ENC_KEY", "").strip() or os.getenv("IOT_ENC_KEY", "").strip()
    if not key_raw:
        raise ValueError("Missing VMT_ENC_KEY in environment.")

    # 1) Try hex decode first when the string looks hex-ish.
    if len(key_raw) % 2 == 0:
        try:
            return _normalize_aes256_key(bytes.fromhex(key_raw))
        except ValueError:
            pass

    # 2) Try standard base64.
    b64_decoded = _decode_b64_maybe(key_raw, urlsafe=False)
    if b64_decoded is not None:
        return _normalize_aes256_key(b64_decoded)

    # 3) Try URL-safe base64.
    b64url_decoded = _decode_b64_maybe(key_raw, urlsafe=True)
    if b64url_decoded is not None:
        return _normalize_aes256_key(b64url_decoded)

    # 4) Fallback to raw bytes and normalize.
    return _normalize_aes256_key(key_raw.encode("utf-8"))


def _encrypt_enc1(inner_payload: dict, kid: str) -> str:
    """
    Encrypt inner payload with AES-256-GCM and return ENC1 JSON string.
    """
    key = _load_enc_key()
    aesgcm = AESGCM(key)

    iv = os.urandom(12)
    body_nonce = token_hex(16)
    ts = str(int(time.time() * 1000))

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

    return decoded if isinstance(decoded, dict) else {"data": decoded}


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

    enc1_json_body = _encrypt_enc1(inner_payload, kid=kid)
    timestamp = str(int(time.time() * 1000))
    request_nonce = token_hex(16)
    signature = _build_signature(
        app_secret=app_secret,
        app_key=app_key,
        timestamp=timestamp,
        nonce=request_nonce,
        enc1_json_body=enc1_json_body,
    )

    headers = {
        "X-App-Key": app_key,
        "X-Timestamp": timestamp,
        "X-Nonce": request_nonce,
        "X-Signature": signature,
        "X-Region": region,
        "Content-Type": "application/json",
    }
    url = f"{base_url}{command_path}"

    response = requests.post(url, data=enc1_json_body, headers=headers, timeout=15)
    response.raise_for_status()
    try:
        payload = response.json()
    except ValueError:
        payload = {"status_code": response.status_code, "raw": response.text}
    return _decrypt_enc1_response(payload)


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
