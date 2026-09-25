#!/usr/bin/env python3
"""
Verifier for TACACS+ administrative logins with AD password + TOTP.

Expected password format on the network device:

    <active-directory-password><6-digit-totp>

Examples:
    /opt/radius-backend/venv/bin/python scripts/verify_tacacs_mfa.py \
      --username jdiaz --password 'MyADPassword123456' --json
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.database import execute, execute_many, query  # noqa: E402
from core.mfa import MFA_TABLE_STATEMENTS, decrypt_secret, split_password_otp, verify_totp_code  # noqa: E402


DEFAULT_DOMAIN = "AXIO"


def ensure_tables():
    execute_many(MFA_TABLE_STATEMENTS)


def emit(payload, as_json=False):
    if as_json:
        print(json.dumps(payload, ensure_ascii=True))
    else:
        print(payload.get("reason") or ("ok" if payload.get("ok") else "fail"))


def log_event(username, action, result, detail=None):
    try:
        execute(
            """
            INSERT INTO axio_mfa_events (username, action, result, detail)
            VALUES (%s, %s, %s, %s)
            """,
            (username, action, result, json.dumps(detail or {})),
        )
    except Exception:
        pass


def authenticate_ad(username, password, domain=DEFAULT_DOMAIN):
    try:
        result = subprocess.run(
            [
                "/usr/bin/ntlm_auth",
                "--request-nt-key",
                f"--domain={domain}",
                f"--username={username}",
                f"--password={password}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0, (result.stdout or result.stderr or "").strip()
    except Exception as exc:
        return False, str(exc)


def load_mfa_user(username):
    ensure_tables()
    return query(
        """
        SELECT username, secret_encrypted, enabled, required, last_time_step
        FROM axio_mfa_users
        WHERE username = %s
        """,
        (username,),
        fetchone=True,
    )


def mark_success(username, step=None):
    if step is None:
        execute(
            """
            UPDATE axio_mfa_users
            SET failed_attempts = 0, last_success_at = %s
            WHERE username = %s
            """,
            (datetime.utcnow(), username),
        )
    else:
        execute(
            """
            UPDATE axio_mfa_users
            SET failed_attempts = 0, last_success_at = %s, last_time_step = %s
            WHERE username = %s
            """,
            (datetime.utcnow(), int(step), username),
        )


def mark_failure(username, reason):
    execute(
        """
        UPDATE axio_mfa_users
        SET failed_attempts = failed_attempts + 1, last_failure_at = %s
        WHERE username = %s
        """,
        (datetime.utcnow(), username),
    )
    log_event(username, "tacacs_login", "fail", {"reason": reason})


def verify_login(username, combined_password, domain=DEFAULT_DOMAIN):
    username = (username or "").strip()
    if not username:
        return {"ok": False, "reason": "missing_username"}

    row = load_mfa_user(username)
    if not row:
        ad_ok, detail = authenticate_ad(username, combined_password, domain=domain)
        log_event(username, "tacacs_login", "success" if ad_ok else "fail", {"mode": "ad_only"} if ad_ok else {"reason": "ad_reject", "detail": detail})
        return {"ok": ad_ok, "username": username, "reason": "ad_only_ok" if ad_ok else "ad_reject"}

    enabled = bool(row.get("enabled"))
    required = bool(row.get("required"))

    if not enabled:
        if required:
            mark_failure(username, "mfa_required_not_enrolled")
            return {"ok": False, "username": username, "reason": "mfa_required_not_enrolled"}

        ad_ok, detail = authenticate_ad(username, combined_password, domain=domain)
        log_event(username, "tacacs_login", "success" if ad_ok else "fail", {"mode": "ad_only_mfa_disabled"} if ad_ok else {"reason": "ad_reject", "detail": detail})
        if ad_ok:
            mark_success(username)
        else:
            mark_failure(username, "ad_reject")
        return {"ok": ad_ok, "username": username, "reason": "ad_only_ok" if ad_ok else "ad_reject"}

    ad_password, otp = split_password_otp(combined_password)
    if not otp:
        mark_failure(username, "missing_totp")
        return {"ok": False, "username": username, "reason": "missing_totp"}

    ad_ok, detail = authenticate_ad(username, ad_password, domain=domain)
    if not ad_ok:
        mark_failure(username, "ad_reject")
        return {"ok": False, "username": username, "reason": "ad_reject", "detail": detail}

    if not row.get("secret_encrypted"):
        mark_failure(username, "missing_secret")
        return {"ok": False, "username": username, "reason": "missing_secret"}

    try:
        secret = decrypt_secret(row["secret_encrypted"])
    except ValueError as exc:
        mark_failure(username, "secret_decrypt_error")
        return {"ok": False, "username": username, "reason": "secret_decrypt_error", "detail": str(exc)}

    last_step = row.get("last_time_step")
    ok, step = verify_totp_code(secret, otp, last_time_step=last_step, valid_window=1)
    if not ok:
        mark_failure(username, "invalid_totp")
        return {"ok": False, "username": username, "reason": "invalid_totp"}

    mark_success(username, step)
    log_event(username, "tacacs_login", "success", {"mode": "ad_totp"})
    return {"ok": True, "username": username, "reason": "ad_totp_ok"}


def main():
    parser = argparse.ArgumentParser(description="Validate TACACS AD password + TOTP.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--domain", default=DEFAULT_DOMAIN)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    try:
        result = verify_login(args.username, args.password, domain=args.domain)
    except Exception as exc:
        result = {"ok": False, "reason": "internal_error", "detail": str(exc)}
        emit(result, args.as_json)
        return 2

    emit(result, args.as_json)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
