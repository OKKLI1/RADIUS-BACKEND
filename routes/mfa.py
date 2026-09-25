import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from core.database import execute, execute_many, query
from core.mfa import (
    MFA_TABLE_STATEMENTS,
    build_otpauth_uri,
    decrypt_secret,
    encrypt_secret,
    generate_totp_secret,
    make_qr_data_url,
    verify_totp_code,
)
from core.security import require_admin


router = APIRouter(prefix="/api/mfa", tags=["TACACS MFA"], dependencies=[Depends(require_admin)])


class EnrollPayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    required: bool = True
    issuer: str = Field(default="AxioRadius", max_length=80)


class ConfirmPayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    code: str = Field(..., min_length=4, max_length=16)


class UsernamePayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)


class RequirementPayload(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    required: bool


def ensure_mfa_tables():
    execute_many(MFA_TABLE_STATEMENTS)


def clean_username(username: str) -> str:
    value = str(username or "").strip()
    if not value:
        raise HTTPException(400, "Username requerido.")
    if len(value) > 128:
        raise HTTPException(400, "Username demasiado largo.")
    return value


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def log_mfa_event(username: str, action: str, result: str, detail: Optional[dict] = None, ip_address: Optional[str] = None):
    try:
        execute(
            """
            INSERT INTO axio_mfa_events (username, action, result, detail, ip_address)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (username, action, result, json.dumps(detail or {}), ip_address),
        )
    except Exception:
        pass


def get_mfa_row(username: str):
    ensure_mfa_tables()
    return query("SELECT * FROM axio_mfa_users WHERE username = %s", (username,), fetchone=True)


def create_enrollment(username: str, required: bool, issuer: str, request: Request, action: str = "enroll"):
    ensure_mfa_tables()
    username = clean_username(username)
    issuer = (issuer or "AxioRadius").strip() or "AxioRadius"
    secret = generate_totp_secret()
    encrypted = encrypt_secret(secret)
    label = f"{issuer}:{username}"
    now = datetime.utcnow()

    execute(
        """
        INSERT INTO axio_mfa_users
            (username, secret_encrypted, enabled, required, issuer, label, failed_attempts, last_time_step, created_at)
        VALUES (%s, %s, 0, %s, %s, %s, 0, NULL, %s)
        ON DUPLICATE KEY UPDATE
            secret_encrypted = VALUES(secret_encrypted),
            enabled = 0,
            required = VALUES(required),
            issuer = VALUES(issuer),
            label = VALUES(label),
            failed_attempts = 0,
            last_time_step = NULL,
            last_failure_at = NULL
        """,
        (username, encrypted, int(required), issuer, label, now),
    )

    otpauth_url = build_otpauth_uri(username, secret, issuer=issuer)
    log_mfa_event(username, action, "pending", {"required": required}, client_ip(request))
    return {
        "ok": True,
        "username": username,
        "issuer": issuer,
        "required": required,
        "otpauth_url": otpauth_url,
        "qr_data_url": make_qr_data_url(otpauth_url),
        "manual_secret": secret,
    }


@router.get("/users")
def list_mfa_users():
    ensure_mfa_tables()
    return query(
        """
        SELECT
            op.username,
            op.role,
            op.auth_method,
            op.active,
            COALESCE(m.enabled, 0) AS mfa_enabled,
            COALESCE(m.required, 0) AS mfa_required,
            CASE WHEN m.secret_encrypted IS NULL OR m.secret_encrypted = '' THEN 0 ELSE 1 END AS has_secret,
            m.issuer,
            m.label,
            m.failed_attempts,
            m.last_success_at,
            m.last_failure_at,
            m.created_at,
            m.updated_at
        FROM axio_operators op
        LEFT JOIN axio_mfa_users m ON m.username = op.username
        UNION ALL
        SELECT
            m.username,
            NULL AS role,
            NULL AS auth_method,
            1 AS active,
            m.enabled AS mfa_enabled,
            m.required AS mfa_required,
            CASE WHEN m.secret_encrypted IS NULL OR m.secret_encrypted = '' THEN 0 ELSE 1 END AS has_secret,
            m.issuer,
            m.label,
            m.failed_attempts,
            m.last_success_at,
            m.last_failure_at,
            m.created_at,
            m.updated_at
        FROM axio_mfa_users m
        LEFT JOIN axio_operators op ON op.username = m.username
        WHERE op.id IS NULL
        ORDER BY username
        """
    )


@router.get("/events")
def list_mfa_events(limit: int = 100, username: Optional[str] = None):
    ensure_mfa_tables()
    limit = max(1, min(int(limit or 100), 500))
    if username:
        return query(
            """
            SELECT id, username, action, result, detail, ip_address, created_at
            FROM axio_mfa_events
            WHERE username = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (clean_username(username), limit),
        )
    return query(
        """
        SELECT id, username, action, result, detail, ip_address, created_at
        FROM axio_mfa_events
        ORDER BY created_at DESC
        LIMIT %s
        """,
        (limit,),
    )


@router.post("/enroll")
def enroll_user(data: EnrollPayload, request: Request):
    return create_enrollment(data.username, data.required, data.issuer, request, "enroll")


@router.post("/reset")
def reset_user(data: EnrollPayload, request: Request):
    return create_enrollment(data.username, data.required, data.issuer, request, "reset")


@router.post("/confirm")
def confirm_enrollment(data: ConfirmPayload, request: Request):
    username = clean_username(data.username)
    row = get_mfa_row(username)
    if not row or not row.get("secret_encrypted"):
        raise HTTPException(404, "No hay enrolamiento pendiente para este usuario.")

    try:
        secret = decrypt_secret(row["secret_encrypted"])
    except ValueError as exc:
        raise HTTPException(500, str(exc)) from exc

    ok, _step = verify_totp_code(secret, data.code, allow_reuse=True)
    if not ok:
        execute(
            """
            UPDATE axio_mfa_users
            SET failed_attempts = failed_attempts + 1, last_failure_at = %s
            WHERE username = %s
            """,
            (datetime.utcnow(), username),
        )
        log_mfa_event(username, "confirm", "fail", {"reason": "invalid_code"}, client_ip(request))
        raise HTTPException(400, "Codigo TOTP invalido.")

    execute(
        """
        UPDATE axio_mfa_users
        SET enabled = 1, required = 1, failed_attempts = 0,
            last_time_step = NULL, last_success_at = %s
        WHERE username = %s
        """,
        (datetime.utcnow(), username),
    )
    log_mfa_event(username, "confirm", "success", None, client_ip(request))
    return {"ok": True, "username": username, "enabled": True}


@router.post("/disable")
def disable_user(data: UsernamePayload, request: Request):
    username = clean_username(data.username)
    ensure_mfa_tables()
    execute(
        """
        INSERT INTO axio_mfa_users (username, enabled, required)
        VALUES (%s, 0, 0)
        ON DUPLICATE KEY UPDATE enabled = 0, required = 0
        """,
        (username,),
    )
    log_mfa_event(username, "disable", "success", None, client_ip(request))
    return {"ok": True, "username": username, "enabled": False, "required": False}


@router.post("/requirement")
def set_requirement(data: RequirementPayload, request: Request):
    username = clean_username(data.username)
    ensure_mfa_tables()
    execute(
        """
        INSERT INTO axio_mfa_users (username, required)
        VALUES (%s, %s)
        ON DUPLICATE KEY UPDATE required = VALUES(required)
        """,
        (username, int(data.required)),
    )
    log_mfa_event(username, "requirement", "success", {"required": data.required}, client_ip(request))
    return {"ok": True, "username": username, "required": data.required}


@router.post("/verify-code")
def verify_code(data: ConfirmPayload, request: Request):
    username = clean_username(data.username)
    row = get_mfa_row(username)
    if not row or not row.get("secret_encrypted"):
        raise HTTPException(404, "Usuario sin secreto MFA.")
    if not row.get("enabled"):
        raise HTTPException(400, "El MFA de este usuario aun no esta habilitado.")

    try:
        secret = decrypt_secret(row["secret_encrypted"])
    except ValueError as exc:
        raise HTTPException(500, str(exc)) from exc

    ok, _step = verify_totp_code(secret, data.code, allow_reuse=True)
    log_mfa_event(username, "verify_code", "success" if ok else "fail", None, client_ip(request))
    if not ok:
        raise HTTPException(400, "Codigo TOTP invalido.")
    return {"ok": True, "username": username}


@router.get("/summary")
def mfa_summary():
    ensure_mfa_tables()
    row = query(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END) AS enabled,
            SUM(CASE WHEN required = 1 THEN 1 ELSE 0 END) AS required,
            SUM(CASE WHEN required = 1 AND enabled = 0 THEN 1 ELSE 0 END) AS pending
        FROM axio_mfa_users
        """,
        fetchone=True,
    ) or {}
    return {
        "total": int(row.get("total") or 0),
        "enabled": int(row.get("enabled") or 0),
        "required": int(row.get("required") or 0),
        "pending": int(row.get("pending") or 0),
    }
