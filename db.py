"""Nayax SQS → SQL: transactions + product lines + full JSON backup."""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Generator, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

log = logging.getLogger(__name__)

_DEFAULT_SQLITE = "sqlite:///./transactions.db"


def _running_on_railway() -> bool:
    return bool(
        os.environ.get("RAILWAY_ENVIRONMENT")
        or os.environ.get("RAILWAY_SERVICE_ID")
        or os.environ.get("RAILWAY_PROJECT_ID")
    )


class Base(DeclarativeBase):
    pass


class NayaxTransaction(Base):
    """One row per Nayax transaction (upsert by nayax_transaction_id when set)."""

    __tablename__ = "nayax_transactions"
    __table_args__ = (UniqueConstraint("nayax_transaction_id", name="uq_nayax_transaction_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Last SQS delivery (audit / debugging)
    sqs_message_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    nayax_transaction_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    remote_start_transaction_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)

    payment_method_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    site_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    machine_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    machine_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    void: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)

    currency: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    se_value: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 4), nullable=True)
    authorization_value: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 4), nullable=True)
    payed_value: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 4), nullable=True)
    settlement_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    authorization_time: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    pay_serv_trans_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    authorization_rrn: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    payment_method_description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    recognition_description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    machine_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    machine_group: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    operator_identifier: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    actor_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True, index=True)
    actor_description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    location_code: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    location_description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    area_description: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    consumer_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    card_first_4: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    card_last_4: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    display_card_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    card_type: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # Complete raw message as received (always store for forward compatibility)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    products: Mapped[list["NayaxTransactionProduct"]] = relationship(
        "NayaxTransactionProduct",
        back_populates="transaction",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class NayaxTransactionProduct(Base):
    """Line items from Data.Products[]."""

    __tablename__ = "nayax_transaction_products"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("nayax_transactions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    line_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    product_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    product_group: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    product_pa_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    product_code_in_map: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    amount_bruto: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 4), nullable=True)
    discount_amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 4), nullable=True)
    discount_percentage: Mapped[Optional[Decimal]] = mapped_column(Numeric(9, 4), nullable=True)

    payload_json: Mapped[str] = mapped_column(Text, nullable=False)

    transaction: Mapped[NayaxTransaction] = relationship("NayaxTransaction", back_populates="products")


class AppUser(Base):
    """Dashboard users: username + password; permissions via app_user_permissions or is_superuser."""

    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Self-service signup: pending until admin approves (admin-created users are always approved).
    review_status: Mapped[str] = mapped_column(String(32), nullable=False, default="approved")
    email: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    registration_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    permissions: Mapped[list["AppUserPermission"]] = relationship(
        "AppUserPermission",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class AppUserPermission(Base):
    __tablename__ = "app_user_permissions"
    __table_args__ = (UniqueConstraint("user_id", "permission", name="uq_app_user_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("app_users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission: Mapped[str] = mapped_column(String(128), nullable=False)

    user: Mapped[AppUser] = relationship("AppUser", back_populates="permissions")


def _normalize_database_url(url: str) -> str:
    """Railway/Heroku use postgres:// or postgresql://; SQLAlchemy+psycopg3 needs postgresql+psycopg://."""
    u = url.strip()
    if u.startswith("postgresql+psycopg://"):
        return u
    if u.startswith("postgres://"):
        return "postgresql+psycopg://" + u.removeprefix("postgres://")
    if u.startswith("postgresql://"):
        return "postgresql+psycopg://" + u.removeprefix("postgresql://")
    return u


def _engine_url() -> str:
    """
    Production (Railway): DATABASE_URL must point to PostgreSQL (plugin reference). SQLite is not
    persisted across deploys on Railway.

    Local dev: omit DATABASE_URL to use ./transactions.db, or set DATABASE_URL to Postgres/sqlite explicitly.
    """
    raw = os.environ.get("DATABASE_URL", "").strip()
    if not raw:
        if _running_on_railway():
            raise RuntimeError(
                "DATABASE_URL is required on Railway. In the Railway dashboard: New → Database → "
                "PostgreSQL, then on this service Variables → New Variable → Reference → "
                "select Postgres → DATABASE_URL. Redeploy."
            )
        return _DEFAULT_SQLITE
    if raw.startswith("sqlite"):
        if _running_on_railway():
            raise RuntimeError(
                "On Railway use PostgreSQL (DATABASE_URL from the Postgres plugin), not sqlite:// — "
                "container disk is ephemeral."
            )
        return raw
    return _normalize_database_url(raw)


def _connect_args(url: str) -> dict[str, Any]:
    if url.startswith("sqlite"):
        return {"check_same_thread": False}
    extra = os.environ.get("PGSSLMODE", "").strip()
    if extra:
        return {"sslmode": extra}
    lowered = url.lower()
    if "sslmode=" in lowered:
        return {}
    # Railway public DB proxies usually require TLS
    if "proxy.rlwy.net" in lowered or ".railway.app" in lowered:
        return {"sslmode": "require"}
    return {}


def _make_engine() -> Engine:
    url = _engine_url()
    kwargs: dict[str, Any] = {"future": True, "echo": os.environ.get("SQL_ECHO", "").lower() in ("1", "true", "yes")}
    ca = _connect_args(url)
    if ca:
        kwargs["connect_args"] = ca
    return create_engine(url, **kwargs)


engine = _make_engine()
SessionLocal = sessionmaker(engine, class_=Session, autoflush=False, autocommit=False, future=True)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn: Any, _record: Any) -> None:
    if engine.dialect.name == "sqlite":
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _patch_sqlite_app_users_columns(eng: Engine) -> None:
    """Add review columns to existing SQLite DBs (create_all does not alter tables)."""
    if eng.dialect.name != "sqlite":
        return
    with eng.begin() as conn:
        r = conn.execute(text("PRAGMA table_info(app_users)"))
        col_names = {row[1] for row in r}
        stmt: list[str] = []
        if "review_status" not in col_names:
            stmt.append(
                "ALTER TABLE app_users ADD COLUMN review_status VARCHAR(32) NOT NULL DEFAULT 'approved'"
            )
        if "email" not in col_names:
            stmt.append("ALTER TABLE app_users ADD COLUMN email VARCHAR(256)")
        if "registration_note" not in col_names:
            stmt.append("ALTER TABLE app_users ADD COLUMN registration_note TEXT")
        for sql in stmt:
            conn.execute(text(sql))


def _ensure_postgres_dashboard_users(eng: Engine) -> None:
    """
    Idempotent: ensure app_users and app_user_permissions exist before running *.sql
    migrations. Covers cases where create_all did not create them (or DB was from an
    old deploy) so registration/auth does not 500 on missing table.
    """
    if eng.dialect.name != "postgresql":
        return
    statements = [
        """
        CREATE TABLE IF NOT EXISTS app_users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(128) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT TRUE,
            is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS app_user_permissions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,
            permission VARCHAR(128) NOT NULL,
            CONSTRAINT uq_app_user_permission UNIQUE (user_id, permission)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_app_user_permissions_user_id ON app_user_permissions(user_id)",
        "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS review_status VARCHAR(32) NOT NULL DEFAULT 'approved'",
        "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email VARCHAR(256)",
        "ALTER TABLE app_users ADD COLUMN IF NOT EXISTS registration_note TEXT",
    ]
    with eng.begin() as conn:
        for raw in statements:
            sql = raw.strip()
            if sql:
                conn.execute(text(sql))
    log.info("Postgres: ensured app_users and app_user_permissions (if missing).")


def _apply_postgres_migrations(eng: Engine) -> None:
    """Run SQL files under migrations/ for existing Postgres DBs (e.g. int4 → bigint)."""
    if eng.dialect.name != "postgresql":
        return
    mig_dir = Path(__file__).resolve().parent / "migrations"
    if not mig_dir.is_dir():
        return
    for path in sorted(mig_dir.glob("*.sql")):
        sql = path.read_text(encoding="utf-8").strip()
        if not sql:
            continue
        try:
            with eng.begin() as conn:
                conn.execute(text(sql))
            log.debug("Postgres migration script OK: %s", path.name)
        except Exception:
            log.exception("Postgres migration failed: %s", path.name)
            raise


def init_db() -> None:
    Base.metadata.create_all(engine)
    _patch_sqlite_app_users_columns(engine)
    _ensure_postgres_dashboard_users(engine)
    _apply_postgres_migrations(engine)
    url = _engine_url()
    if url.startswith("sqlite"):
        log.info(
            "SQL ready (SQLite file, shared by consumer+API in one container): %s",
            url.split("///")[-1] if "///" in url else url,
        )
    else:
        log.info(
            "SQL ready (shared PostgreSQL via DATABASE_URL): %s",
            url.split("@")[-1] if "@" in url else url[:48] + "...",
        )


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _pick_int(payload: dict[str, Any], *keys: str, nested_data: bool = True) -> Optional[int]:
    for k in keys:
        v = payload.get(k)
        if v is not None and v != "":
            try:
                return int(v)
            except (TypeError, ValueError):
                pass
    if nested_data:
        data = payload.get("Data")
        if isinstance(data, dict):
            for k in keys:
                v = data.get(k)
                if v is not None and v != "":
                    try:
                        return int(v)
                    except (TypeError, ValueError):
                        pass
    return None


def _pick_str(payload: dict[str, Any], *keys: str) -> Optional[str]:
    for k in keys:
        v = payload.get(k)
        if v is not None and v != "":
            return str(v)
    data = payload.get("Data")
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if v is not None and v != "":
                return str(v)
    return None


def _pick_bool(payload: dict[str, Any], *keys: str) -> Optional[bool]:
    for k in keys:
        if k in payload and payload[k] is not None:
            return bool(payload[k])
    data = payload.get("Data")
    if isinstance(data, dict):
        for k in keys:
            if k in data and data[k] is not None:
                return bool(data[k])
    return None


def _pick_decimal(payload: dict[str, Any], *keys: str) -> Optional[Decimal]:
    for k in keys:
        v = payload.get(k)
        if v is not None and v != "":
            try:
                return Decimal(str(v))
            except (InvalidOperation, ValueError, TypeError):
                pass
    data = payload.get("Data")
    if isinstance(data, dict):
        for k in keys:
            v = data.get(k)
            if v is not None and v != "":
                try:
                    return Decimal(str(v))
                except (InvalidOperation, ValueError, TypeError):
                    pass
    return None


def _consumer_id_str(payload: dict[str, Any]) -> Optional[str]:
    s = _pick_str(payload, "Consumer ID")
    if s:
        return s
    v = _pick_int(payload, "Consumer ID")
    return str(v) if v is not None else None


def _replace_products(session: Session, parent_id: int, payload: dict[str, Any]) -> None:
    session.execute(delete(NayaxTransactionProduct).where(NayaxTransactionProduct.parent_id == parent_id))
    data = payload.get("Data")
    if not isinstance(data, dict):
        return
    raw_products = data.get("Products")
    if not isinstance(raw_products, list):
        return
    for idx, item in enumerate(raw_products):
        if not isinstance(item, dict):
            continue
        line_json = json.dumps(item, ensure_ascii=False)
        session.add(
            NayaxTransactionProduct(
                parent_id=parent_id,
                line_index=idx,
                product_name=_pick_str(item, "Product Name"),
                product_group=_pick_str(item, "Product Group"),
                product_pa_code=_pick_str(item, "Product PA Code"),
                product_code_in_map=_pick_int(item, "Product Code in Map", nested_data=False),
                amount_bruto=_pick_decimal(item, "Product Bruto"),
                discount_amount=_pick_decimal(item, "Product Discount Amount"),
                discount_percentage=_pick_decimal(item, "Product Discount Percentage"),
                payload_json=line_json,
            )
        )


def _apply_row_fields(row: NayaxTransaction, payload: dict[str, Any], body: str, sqs_message_id: Optional[str]) -> None:
    row.sqs_message_id = sqs_message_id
    row.nayax_transaction_id = _pick_int(payload, "TransactionId", "Transaction ID")
    row.remote_start_transaction_id = _pick_int(payload, "RemoteStartTransactionId")
    row.payment_method_id = _pick_int(payload, "PaymentMethodId", "Payment Method ID (1)")
    row.site_id = _pick_int(payload, "SiteId", "Site ID")
    row.machine_id = _pick_int(payload, "MachineId")
    row.machine_time = _pick_str(payload, "MachineTime", "Machine AuTime")
    row.void = _pick_bool(payload, "Void")

    row.currency = _pick_str(payload, "Currency")
    row.se_value = _pick_decimal(payload, "SeValue")
    row.authorization_value = _pick_decimal(payload, "Authorization Value")
    row.payed_value = _pick_decimal(payload, "Payed Value")
    row.settlement_time = _pick_str(payload, "Settlement Time")
    row.authorization_time = _pick_str(payload, "Authorization Time")

    row.pay_serv_trans_id = _pick_str(payload, "PayServTransid")

    row.authorization_rrn = _pick_str(payload, "Authorization RRN")

    row.payment_method_description = _pick_str(payload, "Payment Method Description")
    row.recognition_description = _pick_str(payload, "Recognition Description")

    row.machine_name = _pick_str(payload, "Machine Name")
    row.machine_group = _pick_str(payload, "Machine Group")
    row.operator_identifier = _pick_str(payload, "Operator Identifier")

    row.actor_id = _pick_int(payload, "Actor ID")
    row.actor_description = _pick_str(payload, "Actor Description")
    row.location_code = _pick_int(payload, "Location Code")
    row.location_description = _pick_str(payload, "Location Description")
    row.area_description = _pick_str(payload, "Area Description")

    row.consumer_id = _consumer_id_str(payload)
    row.card_first_4 = _pick_str(payload, "Card First 4 Digits")
    row.card_last_4 = _pick_str(payload, "Card Last 4 Digits")
    row.display_card_number = _pick_str(payload, "Display Card Number")
    row.card_type = _pick_str(payload, "Card Type")

    row.payload_json = body
    row.received_at = datetime.now(timezone.utc)


def _product_count(payload: dict[str, Any]) -> int:
    data = payload.get("Data")
    if isinstance(data, dict):
        p = data.get("Products")
        if isinstance(p, list):
            return len(p)
    return 0


def save_transaction_payload(
    payload: dict[str, Any],
    sqs_message_id: Optional[str] = None,
) -> None:
    """Insert or update by nayax_transaction_id; replace product lines."""
    if sqs_message_id == "?":
        sqs_message_id = None

    body = json.dumps(payload, ensure_ascii=False)
    tid = _pick_int(payload, "TransactionId", "Transaction ID")
    n_products = _product_count(payload)

    with session_scope() as session:
        if tid is not None:
            existing = session.scalar(
                select(NayaxTransaction).where(NayaxTransaction.nayax_transaction_id == tid)
            )
            if existing:
                _apply_row_fields(existing, payload, body, sqs_message_id)
                _replace_products(session, existing.id, payload)
                log.info("Updated transaction %s in SQL (%s products)", tid, n_products)
                return

        row = NayaxTransaction()
        _apply_row_fields(row, payload, body, sqs_message_id)
        session.add(row)
        session.flush()
        _replace_products(session, row.id, payload)
        log.info(
            "Inserted transaction %s into SQL (%s products)",
            tid if tid is not None else "(no id)",
            n_products,
        )
