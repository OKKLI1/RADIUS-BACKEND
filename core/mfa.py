import base64
import hashlib
import io
import re
import time
from typing import Optional, Tuple

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken

from core.config import settings


MFA_TABLE_STATEMENTS = [
    (
        """
        CREATE TABLE IF NOT EXISTS axio_mfa_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(128) NOT NULL UNIQUE,
            secret_encrypted TEXT NULL,
            enabled TINYINT(1) NOT NULL DEFAULT 0,
            required TINYINT(1) NOT NULL DEFAULT 1,
            issuer VARCHAR(80) NOT NULL DEFAULT 'AxioRadius',
            label VARCHAR(180) NULL,
            last_time_step BIGINT NULL,
            failed_attempts INT NOT NULL DEFAULT 0,
            last_success_at DATETIME NULL,
            last_failure_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        (),
    ),
    (
        """
        CREATE TABLE IF NOT EXISTS axio_mfa_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(128) NOT NULL,
            action VARCHAR(40) NOT NULL,
            result VARCHAR(20) NOT NULL,
            detail TEXT NULL,
            ip_address VARCHAR(64) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_axio_mfa_events_user_date (username, created_at),
            INDEX idx_axio_mfa_events_action_date (action, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        (),
    ),
]


def _fernet_key() -> bytes:
    raw = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(raw)


def _fernet() -> Fernet:
    return Fernet(_fernet_key())


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("No se pudo descifrar el secreto MFA. Revisa SECRET_KEY.") from exc


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_otpauth_uri(username: str, secret: str, issuer: str = "AxioRadius") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def make_qr_data_url(otpauth_uri: str) -> str:
    image = qrcode.make(otpauth_uri)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def split_password_otp(combined: str) -> Tuple[str, Optional[str]]:
    match = re.match(r"^(.*?)(\d{6})$", combined or "")
    if not match:
        return combined or "", None
    return match.group(1), match.group(2)


def verify_totp_code(
    secret: str,
    code: str,
    last_time_step: Optional[int] = None,
    valid_window: int = 1,
    allow_reuse: bool = False,
) -> Tuple[bool, Optional[int]]:
    code = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code):
        return False, None

    totp = pyotp.TOTP(secret)
    interval = int(totp.interval)
    current_step = int(time.time() // interval)

    for offset in range(-valid_window, valid_window + 1):
        step = current_step + offset
        if step < 0:
            continue
        expected = totp.at(step * interval)
        if pyotp.utils.strings_equal(expected, code):
            if not allow_reuse and last_time_step is not None and step <= int(last_time_step):
                return False, None
            return True, step

    return False, None
