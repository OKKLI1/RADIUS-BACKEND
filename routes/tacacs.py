"""
routes/tacacs.py
Gestion de TACACS+: logs, usuarios locales y perfiles shell.
Solo accesible por admin.
"""
import re
import subprocess
import json
import shutil
import csv
import io
import uuid
import tempfile
import difflib
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from core.security import require_admin

router = APIRouter(prefix="/api/tacacs", tags=["TACACS+"])

TACACS_CFG = "/usr/local/etc/tac_plus-ng/tac_plus-ng.cfg"
TACACS_MANAGED_CFG = "/usr/local/etc/tac_plus-ng/axio_managed_rules.cfg"
ACCESS_LOG = "/var/log/tac_plus-ng/access.log"
ACCOUNTING_LOG = "/var/log/tac_plus-ng/accounting.log"
TACACS_SVC = "tac_plus-ng"
SYSTEMCTL_BIN = shutil.which("systemctl") or "/bin/systemctl"
SUDO_BIN = shutil.which("sudo") or "/usr/bin/sudo"
COMMAND_SETS_FILE = "/usr/local/etc/tac_plus-ng/axio_command_sets.json"
AUTHZ_RULES_FILE = "/usr/local/etc/tac_plus-ng/axio_authorization_rules.json"
AUTH_RULES_FILE = "/usr/local/etc/tac_plus-ng/axio_authentication_rules.json"
DEVICE_GROUPS_FILE = "/usr/local/etc/tac_plus-ng/axio_device_groups.json"
POLICY_VERSIONS_FILE = "/usr/local/etc/tac_plus-ng/axio_policy_versions.json"
POLICY_VERSIONS_DIR = "/usr/local/etc/tac_plus-ng/axio_policy_versions"
PROFILE_PATTERN = re.compile(
    r'profile\s+(\S+)\s*\{(.*?)^\s*\}',
    re.DOTALL | re.MULTILINE,
)

POLICY_TRACKED_FILES = [
    TACACS_CFG,
    COMMAND_SETS_FILE,
    AUTHZ_RULES_FILE,
    AUTH_RULES_FILE,
    DEVICE_GROUPS_FILE,
]
MAX_REDACTED_READ_BYTES = 1024 * 1024  # 1 MiB por archivo redacted
AXIO_MANAGED_INCLUDE_LINE = f"include = {TACACS_MANAGED_CFG}"
PROTECTED_SHELL_PROFILES = {"admins_lvl15", "config_lvl3", "helpdesk_lvl1", "default"}
PROTECTED_SHELL_PROFILES_LOWER = {item.lower() for item in PROTECTED_SHELL_PROFILES}


def _tracked_policy_targets() -> dict[str, Path]:
    targets = {}
    for raw in POLICY_TRACKED_FILES:
        path = Path(raw).resolve()
        targets[str(path)] = path
    return targets


def parse_access_log(lines: list[str]) -> list[dict]:
    """
    Formato: 2026-04-28 12:26:52 -0400 127.0.0.1 jdiaz python_tty0 python_device shell login succeeded
    """
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r'\s+', line)
        if len(parts) < 7:
            continue
        try:
            date_str = f"{parts[0]} {parts[1]}"
            tz = parts[2]
            ip = parts[3]
            user = parts[4]
            tty = parts[5]
            device = parts[6]
            action = ' '.join(parts[7:]) if len(parts) > 7 else ''
            results.append({
                "timestamp": date_str,
                "tz": tz,
                "ip": ip,
                "user": user,
                "tty": tty,
                "device": device,
                "action": action,
                "result": "success" if "succeeded" in action else "fail",
            })
        except Exception:
            continue
    return results


def parse_accounting_log(lines: list[str]) -> list[dict]:
    """
    Formato tipico: 2026-04-28 12:30:00 -0400 IP USER TTY DEVICE start/stop cmd
    """
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r'\s+', line)
        if len(parts) < 6:
            continue
        try:
            results.append({
                "timestamp": f"{parts[0]} {parts[1]}",
                "tz": parts[2] if len(parts) > 2 else "",
                "ip": parts[3] if len(parts) > 3 else "",
                "user": parts[4] if len(parts) > 4 else "",
                "tty": parts[5] if len(parts) > 5 else "",
                "device": parts[6] if len(parts) > 6 else "",
                "action": ' '.join(parts[7:]) if len(parts) > 7 else "",
            })
        except Exception:
            continue
    return results


def read_log(path: str, limit: int = 500) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    lines = p.read_text(errors="replace").splitlines()
    return lines[-limit:]


def parse_log_datetime(value: str) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def parse_filter_datetime(value: Optional[str]) -> Optional[datetime]:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidates = [raw, raw.replace("T", " ")]
    for candidate in candidates:
        try:
            if len(candidate) == 10:
                return datetime.strptime(candidate, "%Y-%m-%d")
            return datetime.strptime(candidate[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            continue
    return None


def build_auth_failure_cause(action: str) -> str:
    text = (action or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if "succeeded" in lowered or "success" in lowered:
        return ""
    if "expired" in lowered:
        return "session_expired"
    if "deny" in lowered or "denied" in lowered:
        return "authorization_denied"
    if "password" in lowered:
        return "invalid_password"
    return "auth_failed"


def normalize_cmd_action(action: str) -> dict:
    text = (action or "").strip()
    if not text:
        return {"command_type": "", "command_name": "", "command_args": ""}
    # TACACS accounting varies by NAS/IOS. Prefer extracting the real command when present.
    lowered = text.lower()
    if " cmd=" in lowered:
        cmd_match = re.search(r"\bcmd=([^\s].*)$", text, re.IGNORECASE)
        if cmd_match:
            cmd_text = cmd_match.group(1).strip().strip('"').strip("'")
            cmd_text = cmd_text.replace("<cr>", "").strip()
            cmd_parts = cmd_text.split()
            return {
                "command_type": "command",
                "command_name": cmd_parts[0] if cmd_parts else "",
                "command_args": " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else "",
            }

    parts = text.split()
    if not parts:
        return {"command_type": "", "command_name": "", "command_args": ""}

    first = parts[0].lower()
    if first in {"start", "stop", "login", "logout"}:
        # Common pattern seen in logs: "stop shell configure terminal <cr>"
        rest = parts[1:]
        if rest and rest[0].lower() == "shell":
            rest = rest[1:]
        cleaned = [token for token in rest if token.lower() != "<cr>"]
        if cleaned:
            return {
                "command_type": "command",
                "command_name": cleaned[0],
                "command_args": " ".join(cleaned[1:]) if len(cleaned) > 1 else "",
            }
        return {"command_type": "session", "command_name": first, "command_args": ""}

    cleaned = [token for token in parts if token.lower() != "<cr>"]
    command_name = cleaned[0] if cleaned else ""
    command_args = " ".join(cleaned[1:]) if len(cleaned) > 1 else ""
    return {"command_type": "command", "command_name": command_name, "command_args": command_args}


def filter_auth_logs(rows: list[dict], username: Optional[str], ip: Optional[str], device: Optional[str], result: Optional[str], q: Optional[str], date_from: Optional[str], date_to: Optional[str]) -> list[dict]:
    filtered = rows
    user_q = (username or "").strip().lower()
    ip_q = (ip or "").strip().lower()
    device_q = (device or "").strip().lower()
    result_q = (result or "").strip().lower()
    free_q = (q or "").strip().lower()
    dt_from = parse_filter_datetime(date_from)
    dt_to = parse_filter_datetime(date_to)
    if user_q:
        filtered = [row for row in filtered if user_q in str(row.get("user", "")).lower()]
    if ip_q:
        filtered = [row for row in filtered if ip_q in str(row.get("ip", "")).lower()]
    if device_q:
        filtered = [row for row in filtered if device_q in str(row.get("device", "")).lower()]
    if result_q in {"success", "fail"}:
        filtered = [row for row in filtered if str(row.get("result", "")).lower() == result_q]
    if free_q:
        filtered = [
            row for row in filtered
            if free_q in str(row.get("user", "")).lower()
            or free_q in str(row.get("ip", "")).lower()
            or free_q in str(row.get("device", "")).lower()
            or free_q in str(row.get("action", "")).lower()
        ]
    if dt_from or dt_to:
        subset = []
        for row in filtered:
            dt = parse_log_datetime(row.get("timestamp", ""))
            if not dt:
                continue
            if dt_from and dt < dt_from:
                continue
            if dt_to and dt > dt_to:
                continue
            subset.append(row)
        filtered = subset
    return filtered


def filter_cmd_logs(rows: list[dict], username: Optional[str], ip: Optional[str], device: Optional[str], command: Optional[str], q: Optional[str], date_from: Optional[str], date_to: Optional[str]) -> list[dict]:
    filtered = rows
    user_q = (username or "").strip().lower()
    ip_q = (ip or "").strip().lower()
    device_q = (device or "").strip().lower()
    command_q = (command or "").strip().lower()
    free_q = (q or "").strip().lower()
    dt_from = parse_filter_datetime(date_from)
    dt_to = parse_filter_datetime(date_to)
    if user_q:
        filtered = [row for row in filtered if user_q in str(row.get("user", "")).lower()]
    if ip_q:
        filtered = [row for row in filtered if ip_q in str(row.get("ip", "")).lower()]
    if device_q:
        filtered = [row for row in filtered if device_q in str(row.get("device", "")).lower()]
    if command_q:
        filtered = [row for row in filtered if command_q in str(row.get("command_name", "")).lower()]
    if free_q:
        filtered = [
            row for row in filtered
            if free_q in str(row.get("user", "")).lower()
            or free_q in str(row.get("ip", "")).lower()
            or free_q in str(row.get("device", "")).lower()
            or free_q in str(row.get("action", "")).lower()
        ]
    if dt_from or dt_to:
        subset = []
        for row in filtered:
            dt = parse_log_datetime(row.get("timestamp", ""))
            if not dt:
                continue
            if dt_from and dt < dt_from:
                continue
            if dt_to and dt > dt_to:
                continue
            subset.append(row)
        filtered = subset
    return filtered


def csv_response(filename: str, headers: list[str], rows: list[dict]) -> Response:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in headers})
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/auth-logs", summary="Logs de autenticacion TACACS+")
@router.get("/auth-logs/", include_in_schema=False)
def get_auth_logs(
    limit: int = 200,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    device: Optional[str] = None,
    result: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    payload: dict = Depends(require_admin),
):
    lines = read_log(ACCESS_LOG, limit)
    parsed = parse_access_log(lines)
    for row in parsed:
        row["failure_cause"] = build_auth_failure_cause(row.get("action", ""))
    filtered = filter_auth_logs(parsed, username, ip, device, result, q, date_from, date_to)
    success_count = sum(1 for row in filtered if row.get("result") == "success")
    fail_count = sum(1 for row in filtered if row.get("result") == "fail")
    filtered.reverse()
    return {
        "total": len(filtered),
        "logs": filtered,
        "stats": {
            "success": success_count,
            "fail": fail_count,
            "source_total": len(parsed),
        },
    }


@router.get("/cmd-logs", summary="Logs de comandos TACACS+")
@router.get("/cmd-logs/", include_in_schema=False)
def get_cmd_logs(
    limit: int = 200,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    device: Optional[str] = None,
    command: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    payload: dict = Depends(require_admin),
):
    lines = read_log(ACCOUNTING_LOG, limit)
    parsed = parse_accounting_log(lines)
    for row in parsed:
        row.update(normalize_cmd_action(row.get("action", "")))
    filtered = filter_cmd_logs(parsed, username, ip, device, command, q, date_from, date_to)
    filtered.reverse()
    return {"total": len(filtered), "logs": filtered, "source_total": len(parsed)}


@router.get("/auth-logs/export", summary="Exportar logs de autenticacion TACACS+ a CSV")
@router.get("/auth-logs/export/", include_in_schema=False)
def export_auth_logs(
    limit: int = 5000,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    device: Optional[str] = None,
    result: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    payload: dict = Depends(require_admin),
):
    lines = read_log(ACCESS_LOG, limit)
    parsed = parse_access_log(lines)
    for row in parsed:
        row["failure_cause"] = build_auth_failure_cause(row.get("action", ""))
    filtered = filter_auth_logs(parsed, username, ip, device, result, q, date_from, date_to)
    filtered.reverse()
    return csv_response(
        "tacacs_auth_logs.csv",
        ["timestamp", "tz", "ip", "user", "tty", "device", "action", "result", "failure_cause"],
        filtered,
    )


@router.get("/cmd-logs/export", summary="Exportar logs de comandos TACACS+ a CSV")
@router.get("/cmd-logs/export/", include_in_schema=False)
def export_cmd_logs(
    limit: int = 5000,
    username: Optional[str] = None,
    ip: Optional[str] = None,
    device: Optional[str] = None,
    command: Optional[str] = None,
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    payload: dict = Depends(require_admin),
):
    lines = read_log(ACCOUNTING_LOG, limit)
    parsed = parse_accounting_log(lines)
    for row in parsed:
        row.update(normalize_cmd_action(row.get("action", "")))
    filtered = filter_cmd_logs(parsed, username, ip, device, command, q, date_from, date_to)
    filtered.reverse()
    return csv_response(
        "tacacs_cmd_logs.csv",
        ["timestamp", "tz", "ip", "user", "tty", "device", "action", "command_type", "command_name", "command_args"],
        filtered,
    )


def read_cfg() -> str:
    return Path(TACACS_CFG).read_text(errors="replace")


def get_local_users_from_cfg(include_password: bool = False) -> list[dict]:
    """Extrae usuarios locales del config; por defecto no incluye password."""
    cfg = read_cfg()
    users = []
    pattern = re.compile(r'user\s+(\S+)\s*\{([^}]*)\}', re.DOTALL)
    for match in pattern.finditer(cfg):
        name = match.group(1)
        body = match.group(2)
        pw_value = None
        if include_password:
            pw_match = re.search(r'password\s+login\s*=\s*clear\s+(\S+)', body)
            pw_value = pw_match.group(1) if pw_match else "***"
        has_password = bool(re.search(r'password\s+login\s*=\s*clear\s+\S+', body, re.IGNORECASE))
        profile_match = re.search(r'profile\s*=\s*(\S+)', body)
        row = {
            "username": name,
            "profile": profile_match.group(1) if profile_match else None,
            "is_local": True,
            "has_password": has_password,
        }
        if include_password:
            row["password"] = pw_value
        users.append(row)
    return users


def sanitize_local_users(users: list[dict]) -> list[dict]:
    sanitized = []
    for user in users:
        sanitized.append({
            "username": user.get("username"),
            "profile": user.get("profile"),
            "is_local": bool(user.get("is_local", True)),
            "has_password": bool(user.get("has_password", False)),
        })
    return sanitized


class TacacsUserCreate(BaseModel):
    username: str
    password: str
    profile: str


class TacacsUserUpdate(BaseModel):
    password: Optional[str] = None
    profile: Optional[str] = None


class TacacsProfileCreate(BaseModel):
    name: str
    priv_level: int = Field(default=1, ge=0, le=15)
    description: Optional[str] = None
    script: Optional[str] = None


class TacacsProfileUpdate(BaseModel):
    priv_level: int = Field(default=1, ge=0, le=15)
    description: Optional[str] = None
    script: Optional[str] = None


class TacacsCommandSetCreate(BaseModel):
    name: str
    default_policy: str = Field(default="deny")
    description: Optional[str] = None
    commands: list[str] = Field(default_factory=list)


class TacacsCommandSetUpdate(BaseModel):
    default_policy: str = Field(default="deny")
    description: Optional[str] = None
    commands: list[str] = Field(default_factory=list)


class TacacsAuthorizationRuleCreate(BaseModel):
    name: str
    priority: int = Field(default=1, ge=1, le=9999)
    description: Optional[str] = None
    shell_profile: str
    command_set: str
    match_accounts: list[str] = Field(default_factory=list)
    match_user_groups: list[str] = Field(default_factory=list)
    match_device_groups: list[str] = Field(default_factory=list)
    enabled: bool = True


class TacacsAuthorizationRuleUpdate(BaseModel):
    priority: int = Field(default=1, ge=1, le=9999)
    description: Optional[str] = None
    shell_profile: str
    command_set: str
    match_accounts: list[str] = Field(default_factory=list)
    match_user_groups: list[str] = Field(default_factory=list)
    match_device_groups: list[str] = Field(default_factory=list)
    enabled: bool = True


class TacacsAuthenticationRuleCreate(BaseModel):
    name: str
    priority: int = Field(default=1, ge=1, le=9999)
    description: Optional[str] = None
    auth_source: str = Field(default="ad")
    allowed_user_groups: list[str] = Field(default_factory=list)
    allowed_accounts: list[str] = Field(default_factory=list)
    device_groups: list[str] = Field(default_factory=list)
    enabled: bool = True


class TacacsAuthenticationRuleUpdate(BaseModel):
    priority: int = Field(default=1, ge=1, le=9999)
    description: Optional[str] = None
    auth_source: str = Field(default="ad")
    allowed_user_groups: list[str] = Field(default_factory=list)
    allowed_accounts: list[str] = Field(default_factory=list)
    device_groups: list[str] = Field(default_factory=list)
    enabled: bool = True


class TacacsDeviceGroupCreate(BaseModel):
    name: str
    description: Optional[str] = None
    devices: list[str] = Field(default_factory=list)


class TacacsDeviceGroupUpdate(BaseModel):
    description: Optional[str] = None
    devices: list[str] = Field(default_factory=list)


class TacacsRulesReorderPayload(BaseModel):
    names: list[str] = Field(default_factory=list)


class TacacsRuleTestPayload(BaseModel):
    username: str
    user_groups: list[str] = Field(default_factory=list)
    device_group: Optional[str] = None
    auth_source: Optional[str] = None


class TacacsPolicySnapshotCreate(BaseModel):
    note: Optional[str] = None


class TacacsPolicyDiffPayload(BaseModel):
    from_version_id: str
    to_version_id: str
    filename: Optional[str] = None
    max_diff_lines: int = Field(default=2000, ge=1, le=20000)
    max_files: int = Field(default=20, ge=1, le=200)
    sort_by: str = Field(default="name")
    include_diff: bool = True
    only_changed: bool = False


class TacacsPolicyRenderApplyPayload(BaseModel):
    restart_service: bool = True
    strict_backup: bool = True


def normalize_tacacs_username(username: str) -> str:
    value = str(username or "").strip()
    if not value:
        raise HTTPException(400, "Username requerido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", value):
        raise HTTPException(400, "Username contiene caracteres no permitidos.")
    return value


def normalize_tacacs_password(password: str) -> str:
    value = str(password or "")
    if not value.strip():
        raise HTTPException(400, "Password requerido.")
    if any(char.isspace() for char in value):
        raise HTTPException(400, "Password no puede contener espacios ni saltos de linea.")
    if any(char in value for char in "{}#"):
        raise HTTPException(400, "Password contiene caracteres no permitidos.")
    return value


def normalize_profile_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise HTTPException(400, "Nombre de perfil requerido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise HTTPException(400, "El nombre del perfil contiene caracteres no permitidos.")
    return value


def normalize_command_set_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise HTTPException(400, "Nombre del command set requerido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\- ]+", value):
        raise HTTPException(400, "El nombre del command set contiene caracteres no permitidos.")
    return value


def normalize_command_policy(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in {"permit", "deny"}:
        raise HTTPException(400, "default_policy debe ser 'permit' o 'deny'.")
    return normalized


def normalize_command_lines(commands: list[str]) -> list[str]:
    cleaned = []
    for command in commands or []:
        line = str(command or "").strip()
        if line:
            cleaned.append(line)
    return cleaned


def normalize_rule_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise HTTPException(400, "Nombre de la regla requerido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\- ]+", value):
        raise HTTPException(400, "El nombre de la regla contiene caracteres no permitidos.")
    return value


def normalize_string_list(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for item in values or []:
        value = str(item or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def normalize_auth_source(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized not in {"ad", "ldap", "local"}:
        raise HTTPException(400, "auth_source debe ser 'ad', 'ldap' o 'local'.")
    return normalized


def normalize_device_group_name(name: str) -> str:
    value = (name or "").strip()
    if not value:
        raise HTTPException(400, "Nombre del device group requerido.")
    if not re.fullmatch(r"[A-Za-z0-9_.:\- /]+", value):
        raise HTTPException(400, "El nombre del device group contiene caracteres no permitidos.")
    return value


def _read_json_list(path: str) -> list:
    file_path = Path(path)
    if not file_path.exists():
        return []
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def atomic_write_text(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Escribe archivo de forma atomica para evitar estados parciales/corruptos."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with open(fd, "w", encoding=encoding) as handle:
            handle.write(content)
            handle.flush()
        tmp_path.replace(target)
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass
        raise


def _write_json_list(path: str, data: list):
    file_path = Path(path)
    atomic_write_text(file_path, json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ensure_restrictive_permissions(file_path)


def _policy_versions() -> list[dict]:
    rows = _read_json_list(POLICY_VERSIONS_FILE)
    rows.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return rows


def _save_policy_versions(rows: list[dict]):
    _write_json_list(POLICY_VERSIONS_FILE, rows)


def ensure_restrictive_permissions(path: Path, file_mode: int = 0o600, dir_mode: int = 0o700) -> None:
    """Aplica permisos restrictivos en sistemas POSIX; ignora errores en entornos no POSIX."""
    try:
        target = Path(path)
        if target.is_dir():
            target.chmod(dir_mode)
        elif target.exists():
            target.chmod(file_mode)
            parent = target.parent
            if parent.exists():
                parent.chmod(dir_mode)
    except Exception:
        pass


def create_policy_snapshot(note: Optional[str], actor: str) -> dict:
    version_id = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:8]
    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    snapshot_dir = Path(POLICY_VERSIONS_DIR) / version_id
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    ensure_restrictive_permissions(snapshot_dir)
    files = []
    tracked_targets = _tracked_policy_targets()
    for src in tracked_targets.values():
        exists = src.exists()
        name = src.name
        redacted_name = f"{name}.redacted"
        files.append({
            "path": str(src),
            "name": name,
            "exists": exists,
            "redacted_name": redacted_name,
        })
        if exists:
            shutil.copy2(src, snapshot_dir / name)
            ensure_restrictive_permissions(snapshot_dir / name)
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
                redacted = redact_sensitive_content(str(src), text)
                redacted_path = snapshot_dir / redacted_name
                atomic_write_text(redacted_path, redacted)
                ensure_restrictive_permissions(redacted_path)
            except Exception:
                pass
    entry = {
        "id": version_id,
        "created_at": created_at,
        "actor": actor,
        "note": (note or "").strip() or "Snapshot manual",
        "files": files,
    }
    rows = _policy_versions()
    rows.insert(0, entry)
    _save_policy_versions(rows)
    return entry


def _find_policy_snapshot(version_id: str) -> Optional[dict]:
    for item in _policy_versions():
        if str(item.get("id")) == version_id:
            return item
    return None


def _get_redacted_snapshot_file(version_id: str, redacted_name: str) -> Optional[Path]:
    snapshot = _find_policy_snapshot(version_id)
    if not snapshot:
        return None
    safe_name = str(redacted_name or "").strip()
    if not safe_name:
        return None
    allowed_names = {
        str(file_info.get("redacted_name") or "").strip()
        for file_info in snapshot.get("files", []) or []
    }
    if safe_name not in allowed_names:
        return None
    snapshot_dir = Path(POLICY_VERSIONS_DIR) / version_id
    candidate = (snapshot_dir / safe_name).resolve()
    if candidate.parent != snapshot_dir.resolve():
        return None
    return candidate if candidate.exists() else None


def _snapshot_redacted_names(version_id: str) -> set[str]:
    snapshot = _find_policy_snapshot(version_id)
    if not snapshot:
        return set()
    names = set()
    for file_info in snapshot.get("files", []) or []:
        redacted_name = str(file_info.get("redacted_name") or "").strip()
        if redacted_name:
            names.add(redacted_name)
    return names


def _read_text_limited(path: Path, max_bytes: int = MAX_REDACTED_READ_BYTES) -> tuple[str, bool, int]:
    raw = path.read_bytes()
    total_bytes = len(raw)
    truncated = total_bytes > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    return raw.decode("utf-8", errors="replace"), truncated, total_bytes


def _quote_cfg_string(value: str) -> str:
    text = str(value or "")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _regex_or_list(values: list[str]) -> str:
    cleaned = [str(v or "").strip() for v in values or [] if str(v or "").strip()]
    if not cleaned:
        return ""
    escaped = [re.escape(v) for v in cleaned]
    if len(escaped) == 1:
        return escaped[0]
    return "(?:" + "|".join(escaped) + ")"


def _rule_match_expr(field: str, values: list[str]) -> Optional[str]:
    pattern = _regex_or_list(values)
    if not pattern:
        return None
    return f"{field} =~ /{pattern}/"


def render_managed_tacacs_policy_cfg() -> str:
    profiles = get_profiles_from_cfg()
    authn_rules = [r for r in read_authentication_rules() if r.get("enabled", True) and not r.get("builtin")]
    authz_rules = [r for r in read_authorization_rules() if r.get("enabled", True) and not r.get("builtin")]
    authz_rules.sort(key=lambda item: (int(item.get("priority", 9999)), str(item.get("name", "")).lower()))
    authn_rules.sort(key=lambda item: (int(item.get("priority", 9999)), str(item.get("name", "")).lower()))

    lines = [
        "# --- BEGIN AXIO MANAGED (autogenerated) ---",
        "# Este archivo se genera desde reglas TACACS del frontend/backend.",
        "# No editar manualmente: los cambios se perderan en el proximo render.",
        "",
    ]

    # Re-render profiles to keep TACACS policy coherent with UI definitions.
    for profile in profiles:
        name = normalize_profile_name(profile.get("name", ""))
        block = render_profile_block(
            name=name,
            priv_level=int(profile.get("priv_level", 1)),
            description=profile.get("description"),
            script=profile.get("script"),
        ).strip("\n")
        lines.append(block)
        lines.append("")

    lines.append("ruleset {")

    # Authentication guard rules (optional): if a rule is matched here we permit shell startup.
    for idx, rule in enumerate(authn_rules, start=1):
        name = normalize_rule_name(rule.get("name", f"authn-{idx}"))
        accounts_expr = _rule_match_expr("user", rule.get("allowed_accounts", []))
        groups_expr = _rule_match_expr("memberof", rule.get("allowed_user_groups", []))
        auth_source = str(rule.get("auth_source") or "").strip().lower()

        lines.append(f"    rule authn_{idx}_{name.replace(' ', '_')} {{")
        lines.append("        script {")
        match_parts = []
        if accounts_expr:
            match_parts.append(f"({accounts_expr})")
        if groups_expr:
            match_parts.append(f"({groups_expr})")
        match_expr = " && ".join(match_parts) if match_parts else "1"
        if auth_source and auth_source != "ad":
            lines.append(f"            # auth_source esperado por regla: {auth_source}")
        lines.append(f"            if ({match_expr}) {{")
        lines.append("                if (service == shell && cmd == \"\") permit")
        lines.append("            }")
        lines.append("        }")
        lines.append("    }")

    # Authorization rules assign profiles and permit.
    for idx, rule in enumerate(authz_rules, start=1):
        name = normalize_rule_name(rule.get("name", f"authz-{idx}"))
        profile_name = normalize_profile_name(str(rule.get("shell_profile") or "default"))
        accounts_expr = _rule_match_expr("user", rule.get("match_accounts", []))
        groups_expr = _rule_match_expr("memberof", rule.get("match_user_groups", []))

        lines.append(f"    rule authz_{idx}_{name.replace(' ', '_')} {{")
        lines.append("        script {")
        match_parts = []
        if accounts_expr:
            match_parts.append(f"({accounts_expr})")
        if groups_expr:
            match_parts.append(f"({groups_expr})")
        match_expr = " && ".join(match_parts) if match_parts else "1"
        lines.append(f"            if ({match_expr}) {{")
        lines.append(f"                profile = {profile_name}")
        lines.append("                permit")
        lines.append("            }")
        lines.append("        }")
        lines.append("    }")

    lines.append("    rule axio_default_deny {")
    lines.append("        script {")
    lines.append("            deny")
    lines.append("        }")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("# --- END AXIO MANAGED ---")
    lines.append("")
    return "\n".join(lines)


def ensure_main_cfg_includes_managed(cfg_text: str) -> str:
    text = str(cfg_text or "")
    if AXIO_MANAGED_INCLUDE_LINE in text:
        return text
    # Include must live inside `id = tac_plus-ng { ... }`; appending at EOF can break parser context.
    marker = "id = tac_plus-ng {"
    start = text.find(marker)
    if start == -1:
        if not text.endswith("\n"):
            text += "\n"
        return text + "\n" + AXIO_MANAGED_INCLUDE_LINE + "\n"

    open_brace = text.find("{", start)
    if open_brace == -1:
        if not text.endswith("\n"):
            text += "\n"
        return text + "\n" + AXIO_MANAGED_INCLUDE_LINE + "\n"

    depth = 0
    end_idx = -1
    for idx in range(open_brace, len(text)):
        char = text[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end_idx = idx
                break

    if end_idx == -1:
        if not text.endswith("\n"):
            text += "\n"
        return text + "\n" + AXIO_MANAGED_INCLUDE_LINE + "\n"

    insertion = f"\n    {AXIO_MANAGED_INCLUDE_LINE}\n"
    return text[:end_idx] + insertion + text[end_idx:]


def redact_sensitive_content(path: str, content: str) -> str:
    target = str(path or "").lower()
    text = str(content or "")
    if target.endswith("tac_plus-ng.cfg"):
        text = re.sub(
            r"(password\s+login\s*=\s*clear\s+)(\S+)",
            r"\1***REDACTED***",
            text,
            flags=re.IGNORECASE,
        )
    return text


def auto_snapshot(action: str, payload: dict) -> None:
    try:
        actor = str(payload.get("sub") or payload.get("username") or "admin")
        create_policy_snapshot(f"AUTO {action}", actor)
    except Exception:
        pass


def parse_profile_block(name: str, body: str) -> dict:
    lines = [line.rstrip() for line in body.splitlines()]
    description = None
    cleaned_lines = []

    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        desc_match = re.match(r'#\s*description\s*:\s*(.+)$', line, re.IGNORECASE)
        if desc_match:
            description = desc_match.group(1).strip()
            continue
        cleaned_lines.append(line)

    script = "\n".join(cleaned_lines).strip()
    wrapped_match = re.match(r"^script\s*\{(.*)\}$", script, re.DOTALL)
    if wrapped_match:
        script = wrapped_match.group(1).strip()
    priv_match = re.search(r'set\s+priv-lvl\s*=\s*(\d+)', script)

    return {
        "name": name,
        "priv_level": int(priv_match.group(1)) if priv_match else 0,
        "description": description,
        "script": script,
    }


def find_profile_span(cfg: str, name: str) -> Optional[tuple[int, int, str]]:
    normalized_name = normalize_profile_name(name)
    header_pattern = re.compile(r'(^[ \t]*profile[ \t]+' + re.escape(normalized_name) + r'[ \t]*\{)', re.MULTILINE)
    match = header_pattern.search(cfg)
    if not match:
        return None

    open_brace = cfg.find("{", match.start())
    if open_brace == -1:
        return None

    depth = 0
    for index in range(open_brace, len(cfg)):
        char = cfg[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                while end < len(cfg) and cfg[end] in "\r\n":
                    end += 1
                block = cfg[match.start():end]
                body = cfg[open_brace + 1:index]
                return match.start(), end, body
    return None


def get_profiles_from_cfg() -> list[dict]:
    """Extrae perfiles shell del config."""
    cfg = read_cfg()
    profiles = []
    header_pattern = re.compile(r'^[ \t]*profile[ \t]+(\S+)[ \t]*\{', re.MULTILINE)
    seen = set()
    for match in header_pattern.finditer(cfg):
        profile_name = match.group(1)
        key = profile_name.lower()
        if key in seen:
            continue
        seen.add(key)
        span = find_profile_span(cfg, profile_name)
        if span:
            _, _, body = span
            profiles.append(parse_profile_block(profile_name, body))
    return profiles


def find_user_span(cfg: str, username: str) -> Optional[tuple[int, int]]:
    normalized_username = normalize_tacacs_username(username)
    header_pattern = re.compile(
        r'(^[ \t]*user[ \t]+' + re.escape(normalized_username) + r'[ \t]*\{)',
        re.MULTILINE,
    )
    match = header_pattern.search(cfg)
    if not match:
        return None

    open_brace = cfg.find("{", match.start())
    if open_brace == -1:
        return None

    depth = 0
    for index in range(open_brace, len(cfg)):
        char = cfg[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                while end < len(cfg) and cfg[end] in "\r\n":
                    end += 1
                return match.start(), end
    return None


def write_user_to_cfg(username: str, password: str, profile: str):
    cfg = read_cfg()
    user_block = (
        f'\n    user {username} {{\n'
        f'        password login = clear {password}\n'
        f'        profile = {profile}\n'
        f'    }}\n'
    )
    cfg = cfg.rstrip()
    if cfg.endswith('}'):
        cfg = cfg[:-1] + user_block + '}\n'
    config_path = Path(TACACS_CFG)
    atomic_write_text(config_path, cfg)
    ensure_restrictive_permissions(config_path)


def remove_user_from_cfg(username: str, must_exist: bool = False) -> bool:
    cfg = read_cfg()
    span = find_user_span(cfg, username)
    if not span:
        if must_exist:
            raise HTTPException(404, "Usuario no encontrado.")
        return False

    start, end = span
    cfg = cfg[:start] + cfg[end:]
    config_path = Path(TACACS_CFG)
    atomic_write_text(config_path, cfg)
    ensure_restrictive_permissions(config_path)
    return True


def render_profile_block(name: str, priv_level: int, description: Optional[str], script: Optional[str]) -> str:
    normalized_name = normalize_profile_name(name)
    body_lines = []

    if description and description.strip():
        body_lines.append(f"# description: {description.strip()}")

    script_lines = [line.rstrip() for line in (script or "").splitlines() if line.strip()]
    if script_lines and script_lines[0].strip().startswith("script"):
        # Si el frontend trae el wrapper completo, nos quedamos con el contenido interno.
        script_text = "\n".join(script_lines).strip()
        wrapped_match = re.match(r"^script\s*\{(.*)\}$", script_text, re.DOTALL)
        if wrapped_match:
            script_lines = [line.rstrip() for line in wrapped_match.group(1).strip().splitlines() if line.strip()]

    has_priv = any(re.search(r'set\s+priv-lvl\s*=', line) for line in script_lines)
    if not has_priv:
        script_lines.insert(0, f"set priv-lvl = {priv_level}")

    body_lines.append("script {")
    body_lines.extend(f"    {line}" for line in script_lines)
    body_lines.append("}")
    indented = "\n".join(f"        {line}" for line in body_lines)
    return f"\n    profile {normalized_name} {{\n{indented}\n    }}\n"


def profile_exists(name: str) -> bool:
    normalized_name = normalize_profile_name(name)
    return any(profile["name"] == normalized_name for profile in get_profiles_from_cfg())


def ensure_predefined_shell_profiles() -> None:
    try:
        current = {p.get("name") for p in get_profiles_from_cfg()}
        if "admins_lvl15" not in current:
            upsert_profile_in_cfg(
                "admins_lvl15",
                15,
                "Predefinido: administradores",
                "if (service == shell) {\nif (cmd == \"\") { set priv-lvl = 15 }\npermit\n}",
            )
        if "config_lvl3" not in current:
            upsert_profile_in_cfg(
                "config_lvl3",
                3,
                "Predefinido: operadores de configuracion",
                "if (service == shell) {\nif (cmd == \"\") { set priv-lvl = 3 }\npermit\n}",
            )
        if "helpdesk_lvl1" not in current:
            upsert_profile_in_cfg(
                "helpdesk_lvl1",
                1,
                "Predefinido: helpdesk lectura basica",
                "if (service == shell) {\nif (cmd == \"\") { set priv-lvl = 1 }\npermit\n}",
            )
    except Exception:
        pass


def upsert_profile_in_cfg(name: str, priv_level: int, description: Optional[str], script: Optional[str]):
    normalized_name = normalize_profile_name(name)
    cfg = read_cfg()
    new_block = render_profile_block(normalized_name, priv_level, description, script)
    span = find_profile_span(cfg, normalized_name)

    if span:
        start, end, _ = span
        replacement = new_block.rstrip("\n")
        cfg = cfg[:start] + replacement + cfg[end:]
    else:
        cfg = cfg.rstrip()
        if cfg.endswith('}'):
            cfg = cfg[:-1] + new_block + '}\n'
        else:
            cfg = cfg + new_block

    config_path = Path(TACACS_CFG)
    atomic_write_text(config_path, cfg)
    ensure_restrictive_permissions(config_path)


def remove_profile_from_cfg(name: str):
    normalized_name = normalize_profile_name(name)
    if normalized_name.lower() in PROTECTED_SHELL_PROFILES_LOWER:
        raise HTTPException(400, f"El perfil '{normalized_name}' no se puede eliminar.")

    cfg = read_cfg()
    span = find_profile_span(cfg, normalized_name)
    if not span:
        raise HTTPException(404, "Perfil no encontrado.")
    start, end, _ = span
    updated = cfg[:start] + cfg[end:]
    config_path = Path(TACACS_CFG)
    atomic_write_text(config_path, updated)
    ensure_restrictive_permissions(config_path)


def command_set_defaults() -> list[dict]:
    return [
        {
            "name": "Authorize All",
            "default_policy": "permit",
            "description": "Permite comandos no listados.",
            "commands": [],
            "builtin": True,
        },
        {
            "name": "No Authorized",
            "default_policy": "deny",
            "description": "Niega comandos no listados.",
            "commands": [],
            "builtin": True,
        },
    ]


def read_command_sets() -> list[dict]:
    path = Path(COMMAND_SETS_FILE)
    if not path.exists():
        return command_set_defaults()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return command_set_defaults()
    except Exception:
        return command_set_defaults()

    result = []
    for item in data:
        try:
            result.append({
                "name": normalize_command_set_name(item.get("name", "")),
                "default_policy": normalize_command_policy(item.get("default_policy", "deny")),
                "description": (item.get("description") or "").strip() or None,
                "commands": normalize_command_lines(item.get("commands", [])),
                "builtin": False,
            })
        except HTTPException:
            continue

    return command_set_defaults() + result


def write_command_sets(items: list[dict]):
    path = Path(COMMAND_SETS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = []
    for item in items:
        if item.get("builtin"):
            continue
        stored.append({
            "name": normalize_command_set_name(item["name"]),
            "default_policy": normalize_command_policy(item["default_policy"]),
            "description": (item.get("description") or "").strip() or None,
            "commands": normalize_command_lines(item.get("commands", [])),
        })
    atomic_write_text(path, json.dumps(stored, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ensure_restrictive_permissions(path)


def authorization_rule_defaults() -> list[dict]:
    return [
        {
            "name": "grp_admins_15",
            "priority": 1,
            "description": "Predefinida: AxioRadius-Admins -> shell nivel 15",
            "shell_profile": "admins_lvl15",
            "command_set": "Authorize All",
            "match_accounts": [],
            "match_user_groups": ["AxioRadius-Admins"],
            "match_device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "grp_config_3",
            "priority": 2,
            "description": "Predefinida: AxioRadius-Config -> shell nivel 3",
            "shell_profile": "config_lvl3",
            "command_set": "Authorize All",
            "match_accounts": [],
            "match_user_groups": ["AxioRadius-Config"],
            "match_device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "grp_helpdesk_1",
            "priority": 3,
            "description": "Predefinida: AxioRadius-Helpdesk -> shell nivel 1",
            "shell_profile": "helpdesk_lvl1",
            "command_set": "Authorize All",
            "match_accounts": [],
            "match_user_groups": ["AxioRadius-Helpdesk"],
            "match_device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "default",
            "priority": 9999,
            "description": "Regla por defecto si no hay coincidencia previa.",
            "shell_profile": "default",
            "command_set": "No Authorized",
            "match_accounts": [],
            "match_user_groups": [],
            "match_device_groups": [],
            "enabled": True,
            "builtin": True,
        },
    ]


def validate_authorization_refs(shell_profile: str, command_set: str):
    ensure_predefined_shell_profiles()
    profile_names = {item["name"] for item in get_profiles_from_cfg()}
    if shell_profile not in profile_names:
        raise HTTPException(400, f"Shell profile '{shell_profile}' no existe.")

    command_set_names = {item["name"] for item in read_command_sets()}
    if command_set not in command_set_names:
        raise HTTPException(400, f"Command set '{command_set}' no existe.")


def read_authorization_rules() -> list[dict]:
    path = Path(AUTHZ_RULES_FILE)
    if not path.exists():
        return authorization_rule_defaults()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return authorization_rule_defaults()
    except Exception:
        return authorization_rule_defaults()

    result = []
    for item in data:
        try:
            result.append({
                "name": normalize_rule_name(item.get("name", "")),
                "priority": int(item.get("priority", 1)),
                "description": (item.get("description") or "").strip() or None,
                "shell_profile": str(item.get("shell_profile") or "").strip(),
                "command_set": str(item.get("command_set") or "").strip(),
                "match_accounts": normalize_string_list(item.get("match_accounts", [])),
                "match_user_groups": normalize_string_list(item.get("match_user_groups", [])),
                "match_device_groups": normalize_string_list(item.get("match_device_groups", [])),
                "enabled": bool(item.get("enabled", True)),
                "builtin": False,
            })
        except Exception:
            continue

    combined = authorization_rule_defaults() + result
    combined.sort(key=lambda item: (item.get("priority", 9999), item["name"].lower()))
    return combined


def write_authorization_rules(items: list[dict]):
    path = Path(AUTHZ_RULES_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = []
    for item in items:
        if item.get("builtin"):
            continue
        validate_authorization_refs(item["shell_profile"], item["command_set"])
        stored.append({
            "name": normalize_rule_name(item["name"]),
            "priority": int(item["priority"]),
            "description": (item.get("description") or "").strip() or None,
            "shell_profile": str(item["shell_profile"]).strip(),
            "command_set": str(item["command_set"]).strip(),
            "match_accounts": normalize_string_list(item.get("match_accounts", [])),
            "match_user_groups": normalize_string_list(item.get("match_user_groups", [])),
            "match_device_groups": normalize_string_list(item.get("match_device_groups", [])),
            "enabled": bool(item.get("enabled", True)),
        })
    atomic_write_text(path, json.dumps(stored, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ensure_restrictive_permissions(path)


def authentication_rule_defaults() -> list[dict]:
    return [
        {
            "name": "auth_admins",
            "priority": 1,
            "description": "Predefinida: AxioRadius-Admins (AD)",
            "auth_source": "ad",
            "allowed_user_groups": ["AxioRadius-Admins"],
            "allowed_accounts": [],
            "device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "auth_config",
            "priority": 2,
            "description": "Predefinida: AxioRadius-Config (AD)",
            "auth_source": "ad",
            "allowed_user_groups": ["AxioRadius-Config"],
            "allowed_accounts": [],
            "device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "auth_helpdesk",
            "priority": 3,
            "description": "Predefinida: AxioRadius-Helpdesk (AD)",
            "auth_source": "ad",
            "allowed_user_groups": ["AxioRadius-Helpdesk"],
            "allowed_accounts": [],
            "device_groups": [],
            "enabled": True,
            "builtin": True,
        },
        {
            "name": "default",
            "priority": 9999,
            "description": "Fallback local si ninguna regla previa coincide.",
            "auth_source": "local",
            "allowed_user_groups": [],
            "allowed_accounts": [],
            "device_groups": [],
            "enabled": True,
            "builtin": True,
        },
    ]


def read_authentication_rules() -> list[dict]:
    path = Path(AUTH_RULES_FILE)
    if not path.exists():
        return authentication_rule_defaults()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return authentication_rule_defaults()
    except Exception:
        return authentication_rule_defaults()

    result = []
    for item in data:
        try:
            result.append({
                "name": normalize_rule_name(item.get("name", "")),
                "priority": int(item.get("priority", 1)),
                "description": (item.get("description") or "").strip() or None,
                "auth_source": normalize_auth_source(item.get("auth_source", "ad")),
                "allowed_user_groups": normalize_string_list(item.get("allowed_user_groups", [])),
                "allowed_accounts": normalize_string_list(item.get("allowed_accounts", [])),
                "device_groups": normalize_string_list(item.get("device_groups", [])),
                "enabled": bool(item.get("enabled", True)),
                "builtin": False,
            })
        except Exception:
            continue

    combined = authentication_rule_defaults() + result
    combined.sort(key=lambda item: (item.get("priority", 9999), item["name"].lower()))
    return combined


def write_authentication_rules(items: list[dict]):
    path = Path(AUTH_RULES_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = []
    for item in items:
        if item.get("builtin"):
            continue
        stored.append({
            "name": normalize_rule_name(item["name"]),
            "priority": int(item["priority"]),
            "description": (item.get("description") or "").strip() or None,
            "auth_source": normalize_auth_source(item.get("auth_source", "ad")),
            "allowed_user_groups": normalize_string_list(item.get("allowed_user_groups", [])),
            "allowed_accounts": normalize_string_list(item.get("allowed_accounts", [])),
            "device_groups": normalize_string_list(item.get("device_groups", [])),
            "enabled": bool(item.get("enabled", True)),
        })
    atomic_write_text(path, json.dumps(stored, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ensure_restrictive_permissions(path)


def read_device_groups() -> list[dict]:
    path = Path(DEVICE_GROUPS_FILE)
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            return []
    except Exception:
        return []

    result = []
    for item in data:
        try:
            result.append({
                "name": normalize_device_group_name(item.get("name", "")),
                "description": (item.get("description") or "").strip() or None,
                "devices": normalize_string_list(item.get("devices", [])),
            })
        except Exception:
            continue

    result.sort(key=lambda item: item["name"].lower())
    return result


def write_device_groups(items: list[dict]):
    path = Path(DEVICE_GROUPS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    stored = []
    for item in items:
        stored.append({
            "name": normalize_device_group_name(item["name"]),
            "description": (item.get("description") or "").strip() or None,
            "devices": normalize_string_list(item.get("devices", [])),
        })
    atomic_write_text(path, json.dumps(stored, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ensure_restrictive_permissions(path)


def validate_device_group_refs(values: list[str]) -> None:
    known = {str(item.get("name") or "").strip().lower() for item in read_device_groups()}
    refs = normalize_string_list(values)
    unknown = [value for value in refs if value.lower() not in known]
    if unknown:
        raise HTTPException(400, "Grupos de dispositivos no validos: " + ", ".join(unknown))


def get_authorization_usage() -> tuple[set[str], set[str], set[str]]:
    used_profiles = set()
    used_command_sets = set()
    used_device_groups = set()
    for rule in read_authorization_rules():
        used_profiles.add(str(rule.get("shell_profile") or "").strip().lower())
        used_command_sets.add(str(rule.get("command_set") or "").strip().lower())
        for value in rule.get("match_device_groups", []) or []:
            used_device_groups.add(str(value or "").strip().lower())
    return used_profiles, used_command_sets, used_device_groups


def get_authentication_device_group_usage() -> set[str]:
    used = set()
    for rule in read_authentication_rules():
        for value in rule.get("device_groups", []) or []:
            used.add(str(value or "").strip().lower())
    return used


def run_systemctl(*args: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        [SUDO_BIN, "-n", SYSTEMCTL_BIN, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _normalize_lookup_set(values: list[str]) -> set[str]:
    return {str(value or "").strip().lower() for value in values or [] if str(value or "").strip()}


def _rule_matches(values: list[str], candidate_values: set[str]) -> bool:
    expected = _normalize_lookup_set(values)
    if not expected:
        return True
    return len(expected.intersection(candidate_values)) > 0


def _evaluate_authentication_rule(payload: TacacsRuleTestPayload) -> Optional[dict]:
    rules = [rule for rule in read_authentication_rules() if rule.get("enabled", True)]
    rules.sort(key=lambda item: (int(item.get("priority", 9999)), item.get("name", "").lower()))
    username = str(payload.username or "").strip().lower()
    user_groups = _normalize_lookup_set(payload.user_groups)
    device_group = str(payload.device_group or "").strip().lower()
    auth_source = str(payload.auth_source or "").strip().lower()
    for rule in rules:
        if auth_source and str(rule.get("auth_source", "")).lower() not in {auth_source, ""}:
            continue
        if not _rule_matches(rule.get("allowed_accounts", []), {username}):
            continue
        if not _rule_matches(rule.get("allowed_user_groups", []), user_groups):
            continue
        if rule.get("device_groups"):
            if not device_group or device_group not in _normalize_lookup_set(rule.get("device_groups", [])):
                continue
        return rule
    return None


def _evaluate_authorization_rule(payload: TacacsRuleTestPayload) -> Optional[dict]:
    rules = [rule for rule in read_authorization_rules() if rule.get("enabled", True)]
    rules.sort(key=lambda item: (int(item.get("priority", 9999)), item.get("name", "").lower()))
    username = str(payload.username or "").strip().lower()
    user_groups = _normalize_lookup_set(payload.user_groups)
    device_group = str(payload.device_group or "").strip().lower()
    for rule in rules:
        if not _rule_matches(rule.get("match_accounts", []), {username}):
            continue
        if not _rule_matches(rule.get("match_user_groups", []), user_groups):
            continue
        if rule.get("match_device_groups"):
            if not device_group or device_group not in _normalize_lookup_set(rule.get("match_device_groups", [])):
                continue
        return rule
    return None


@router.get("/users", summary="Listar usuarios locales TACACS+")
@router.get("/users/", include_in_schema=False)
def list_tacacs_users(payload: dict = Depends(require_admin)):
    return sanitize_local_users(get_local_users_from_cfg(include_password=False))


@router.post("/users", summary="Crear usuario local TACACS+")
@router.post("/users/", include_in_schema=False)
def create_tacacs_user(data: TacacsUserCreate, payload: dict = Depends(require_admin)):
    username = normalize_tacacs_username(data.username)
    password = normalize_tacacs_password(data.password)
    profile = normalize_profile_name(data.profile)
    if not profile_exists(profile):
        raise HTTPException(400, f"Perfil '{profile}' no existe.")
    existing = get_local_users_from_cfg(include_password=False)
    if any(str(user.get("username", "")).lower() == username.lower() for user in existing):
        raise HTTPException(400, f"Usuario '{username}' ya existe.")
    auto_snapshot(f"user.create:{username}", payload)
    write_user_to_cfg(username, password, profile)
    return {"ok": True, "username": username}


@router.put("/users/{username}", summary="Actualizar usuario local TACACS+")
@router.put("/users/{username}/", include_in_schema=False)
def update_tacacs_user(username: str, data: TacacsUserUpdate, payload: dict = Depends(require_admin)):
    normalized_username = normalize_tacacs_username(username)
    existing = get_local_users_from_cfg(include_password=True)
    user = next((item for item in existing if str(item.get("username", "")).lower() == normalized_username.lower()), None)
    if not user:
        raise HTTPException(404, "Usuario no encontrado.")
    new_pw = normalize_tacacs_password(data.password) if data.password is not None else user["password"]
    if str(new_pw or "").strip() == "***":
        raise HTTPException(400, "No se pudo conservar password actual. Define un nuevo password.")
    new_profile = normalize_profile_name(data.profile) if data.profile is not None else user["profile"]
    if new_profile and not profile_exists(new_profile):
        raise HTTPException(400, f"Perfil '{new_profile}' no existe.")
    auto_snapshot(f"user.update:{normalized_username}", payload)
    remove_user_from_cfg(normalized_username)
    write_user_to_cfg(normalized_username, new_pw, new_profile)
    return {"ok": True}


@router.delete("/users/{username}", summary="Eliminar usuario local TACACS+")
@router.delete("/users/{username}/", include_in_schema=False)
def delete_tacacs_user(username: str, payload: dict = Depends(require_admin)):
    normalized_username = normalize_tacacs_username(username)
    auto_snapshot(f"user.delete:{normalized_username}", payload)
    remove_user_from_cfg(normalized_username, must_exist=True)
    return {"ok": True}


@router.get("/profiles", summary="Listar perfiles shell TACACS+")
@router.get("/profiles/", include_in_schema=False)
def list_tacacs_profiles(payload: dict = Depends(require_admin)):
    ensure_predefined_shell_profiles()
    return get_profiles_from_cfg()


@router.post("/profiles", summary="Crear perfil shell TACACS+")
@router.post("/profiles/", include_in_schema=False)
def create_tacacs_profile(data: TacacsProfileCreate, payload: dict = Depends(require_admin)):
    name = normalize_profile_name(data.name)
    if profile_exists(name):
        raise HTTPException(400, f"El perfil '{name}' ya existe.")
    auto_snapshot(f"profile.create:{name}", payload)
    upsert_profile_in_cfg(name, data.priv_level, data.description, data.script)
    return {"ok": True, "name": name}


@router.put("/profiles/{name}", summary="Actualizar perfil shell TACACS+")
@router.put("/profiles/{name}/", include_in_schema=False)
def update_tacacs_profile(name: str, data: TacacsProfileUpdate, payload: dict = Depends(require_admin)):
    normalized_name = normalize_profile_name(name)
    if not profile_exists(normalized_name):
        raise HTTPException(404, "Perfil no encontrado.")
    auto_snapshot(f"profile.update:{normalized_name}", payload)
    upsert_profile_in_cfg(normalized_name, data.priv_level, data.description, data.script)
    return {"ok": True, "name": normalized_name}


@router.delete("/profiles/{name}", summary="Eliminar perfil shell TACACS+")
@router.delete("/profiles/{name}/", include_in_schema=False)
def delete_tacacs_profile(name: str, payload: dict = Depends(require_admin)):
    auto_snapshot(f"profile.delete:{name}", payload)
    remove_profile_from_cfg(name)
    return {"ok": True}


@router.get("/command-sets", summary="Listar command sets TACACS+")
@router.get("/command-sets/", include_in_schema=False)
def list_tacacs_command_sets(payload: dict = Depends(require_admin)):
    return read_command_sets()


@router.post("/command-sets", summary="Crear command set TACACS+")
@router.post("/command-sets/", include_in_schema=False)
def create_tacacs_command_set(data: TacacsCommandSetCreate, payload: dict = Depends(require_admin)):
    name = normalize_command_set_name(data.name)
    existing = read_command_sets()
    if any(item["name"].lower() == name.lower() for item in existing):
        raise HTTPException(400, f"El command set '{name}' ya existe.")

    items = existing + [{
        "name": name,
        "default_policy": normalize_command_policy(data.default_policy),
        "description": (data.description or "").strip() or None,
        "commands": normalize_command_lines(data.commands),
        "builtin": False,
    }]
    auto_snapshot(f"commandset.create:{name}", payload)
    write_command_sets(items)
    return {"ok": True, "name": name}


@router.put("/command-sets/{name}", summary="Actualizar command set TACACS+")
@router.put("/command-sets/{name}/", include_in_schema=False)
def update_tacacs_command_set(name: str, data: TacacsCommandSetUpdate, payload: dict = Depends(require_admin)):
    normalized_name = normalize_command_set_name(name)
    items = read_command_sets()
    updated = False

    for item in items:
        if item["name"].lower() != normalized_name.lower():
            continue
        if item.get("builtin"):
            raise HTTPException(400, "Los command sets integrados no se pueden editar.")
        item["default_policy"] = normalize_command_policy(data.default_policy)
        item["description"] = (data.description or "").strip() or None
        item["commands"] = normalize_command_lines(data.commands)
        updated = True
        break

    if not updated:
        raise HTTPException(404, "Command set no encontrado.")

    auto_snapshot(f"commandset.update:{normalized_name}", payload)
    write_command_sets(items)
    return {"ok": True, "name": normalized_name}


@router.delete("/command-sets/{name}", summary="Eliminar command set TACACS+")
@router.delete("/command-sets/{name}/", include_in_schema=False)
def delete_tacacs_command_set(name: str, payload: dict = Depends(require_admin)):
    normalized_name = normalize_command_set_name(name)
    items = read_command_sets()
    remaining = []
    deleted = False

    for item in items:
        if item["name"].lower() == normalized_name.lower():
            if item.get("builtin"):
                raise HTTPException(400, "Los command sets integrados no se pueden eliminar.")
            deleted = True
            continue
        remaining.append(item)

    if not deleted:
        raise HTTPException(404, "Command set no encontrado.")

    auto_snapshot(f"commandset.delete:{normalized_name}", payload)
    write_command_sets(remaining)
    return {"ok": True}


@router.get("/authorization-rules", summary="Listar reglas de autorizacion TACACS+")
@router.get("/authorization-rules/", include_in_schema=False)
def list_tacacs_authorization_rules(payload: dict = Depends(require_admin)):
    return read_authorization_rules()


@router.post("/authorization-rules", summary="Crear regla de autorizacion TACACS+")
@router.post("/authorization-rules/", include_in_schema=False)
def create_tacacs_authorization_rule(data: TacacsAuthorizationRuleCreate, payload: dict = Depends(require_admin)):
    name = normalize_rule_name(data.name)
    items = read_authorization_rules()
    if any(item["name"].lower() == name.lower() for item in items):
        raise HTTPException(400, f"La regla '{name}' ya existe.")

    validate_authorization_refs(data.shell_profile, data.command_set)
    validate_device_group_refs(data.match_device_groups)
    items.append({
        "name": name,
        "priority": int(data.priority),
        "description": (data.description or "").strip() or None,
        "shell_profile": data.shell_profile,
        "command_set": data.command_set,
        "match_accounts": normalize_string_list(data.match_accounts),
        "match_user_groups": normalize_string_list(data.match_user_groups),
        "match_device_groups": normalize_string_list(data.match_device_groups),
        "enabled": bool(data.enabled),
        "builtin": False,
    })
    auto_snapshot(f"authz.create:{name}", payload)
    write_authorization_rules(items)
    return {"ok": True, "name": name}


@router.put("/authorization-rules/{name}", summary="Actualizar regla de autorizacion TACACS+")
@router.put("/authorization-rules/{name}/", include_in_schema=False)
def update_tacacs_authorization_rule(name: str, data: TacacsAuthorizationRuleUpdate, payload: dict = Depends(require_admin)):
    normalized_name = normalize_rule_name(name)
    items = read_authorization_rules()
    updated = False

    validate_authorization_refs(data.shell_profile, data.command_set)
    validate_device_group_refs(data.match_device_groups)

    for item in items:
        if item["name"].lower() != normalized_name.lower():
            continue
        if item.get("builtin") and str(item.get("name", "")).lower() == "default":
            raise HTTPException(400, "La regla default no se puede editar en esta fase.")
        item["priority"] = int(data.priority)
        item["description"] = (data.description or "").strip() or None
        item["shell_profile"] = data.shell_profile
        item["command_set"] = data.command_set
        item["match_accounts"] = normalize_string_list(data.match_accounts)
        item["match_user_groups"] = normalize_string_list(data.match_user_groups)
        item["match_device_groups"] = normalize_string_list(data.match_device_groups)
        item["enabled"] = bool(data.enabled)
        updated = True
        break

    if not updated:
        raise HTTPException(404, "Regla no encontrada.")

    auto_snapshot(f"authz.update:{normalized_name}", payload)
    write_authorization_rules(items)
    return {"ok": True, "name": normalized_name}


@router.delete("/authorization-rules/{name}", summary="Eliminar regla de autorizacion TACACS+")
@router.delete("/authorization-rules/{name}/", include_in_schema=False)
def delete_tacacs_authorization_rule(name: str, payload: dict = Depends(require_admin)):
    normalized_name = normalize_rule_name(name)
    items = read_authorization_rules()
    remaining = []
    deleted = False

    for item in items:
        if item["name"].lower() == normalized_name.lower():
            if item.get("builtin"):
                raise HTTPException(400, "Las reglas predefinidas no se pueden eliminar.")
            deleted = True
            continue
        remaining.append(item)

    if not deleted:
        raise HTTPException(404, "Regla no encontrada.")

    auto_snapshot(f"authz.delete:{normalized_name}", payload)
    write_authorization_rules(remaining)
    return {"ok": True}


@router.post("/authorization-rules/reorder", summary="Reordenar reglas de autorizacion TACACS+")
@router.post("/authorization-rules/reorder/", include_in_schema=False)
def reorder_tacacs_authorization_rules(data: TacacsRulesReorderPayload, payload: dict = Depends(require_admin)):
    ordered_names = [normalize_rule_name(name) for name in data.names]
    name_index = {name.lower(): idx for idx, name in enumerate(ordered_names)}
    items = read_authorization_rules()
    editable = [item for item in items if not item.get("builtin")]
    if set(name_index.keys()) != {item["name"].lower() for item in editable}:
        raise HTTPException(400, "Debes enviar todos los nombres de reglas editables para reordenar.")
    editable.sort(key=lambda item: name_index[item["name"].lower()])
    for idx, item in enumerate(editable, start=1):
        item["priority"] = idx
    builtins = [item for item in items if item.get("builtin")]
    auto_snapshot("authz.reorder", payload)
    write_authorization_rules(builtins + editable)
    return {"ok": True}


@router.get("/authentication-rules", summary="Listar reglas de autenticacion TACACS+")
@router.get("/authentication-rules/", include_in_schema=False)
def list_tacacs_authentication_rules(payload: dict = Depends(require_admin)):
    return read_authentication_rules()


@router.post("/authentication-rules", summary="Crear regla de autenticacion TACACS+")
@router.post("/authentication-rules/", include_in_schema=False)
def create_tacacs_authentication_rule(data: TacacsAuthenticationRuleCreate, payload: dict = Depends(require_admin)):
    name = normalize_rule_name(data.name)
    items = read_authentication_rules()
    if any(item["name"].lower() == name.lower() for item in items):
        raise HTTPException(400, f"La regla '{name}' ya existe.")

    validate_device_group_refs(data.device_groups)
    items.append({
        "name": name,
        "priority": int(data.priority),
        "description": (data.description or "").strip() or None,
        "auth_source": normalize_auth_source(data.auth_source),
        "allowed_user_groups": normalize_string_list(data.allowed_user_groups),
        "allowed_accounts": normalize_string_list(data.allowed_accounts),
        "device_groups": normalize_string_list(data.device_groups),
        "enabled": bool(data.enabled),
        "builtin": False,
    })
    auto_snapshot(f"auth.create:{name}", payload)
    write_authentication_rules(items)
    return {"ok": True, "name": name}


@router.put("/authentication-rules/{name}", summary="Actualizar regla de autenticacion TACACS+")
@router.put("/authentication-rules/{name}/", include_in_schema=False)
def update_tacacs_authentication_rule(name: str, data: TacacsAuthenticationRuleUpdate, payload: dict = Depends(require_admin)):
    normalized_name = normalize_rule_name(name)
    items = read_authentication_rules()
    updated = False

    validate_device_group_refs(data.device_groups)
    for item in items:
        if item["name"].lower() != normalized_name.lower():
            continue
        if item.get("builtin") and str(item.get("name", "")).lower() == "default":
            raise HTTPException(400, "La regla default no se puede editar en esta fase.")
        item["priority"] = int(data.priority)
        item["description"] = (data.description or "").strip() or None
        item["auth_source"] = normalize_auth_source(data.auth_source)
        item["allowed_user_groups"] = normalize_string_list(data.allowed_user_groups)
        item["allowed_accounts"] = normalize_string_list(data.allowed_accounts)
        item["device_groups"] = normalize_string_list(data.device_groups)
        item["enabled"] = bool(data.enabled)
        updated = True
        break

    if not updated:
        raise HTTPException(404, "Regla no encontrada.")

    auto_snapshot(f"auth.update:{normalized_name}", payload)
    write_authentication_rules(items)
    return {"ok": True, "name": normalized_name}


@router.delete("/authentication-rules/{name}", summary="Eliminar regla de autenticacion TACACS+")
@router.delete("/authentication-rules/{name}/", include_in_schema=False)
def delete_tacacs_authentication_rule(name: str, payload: dict = Depends(require_admin)):
    normalized_name = normalize_rule_name(name)
    items = read_authentication_rules()
    remaining = []
    deleted = False

    for item in items:
        if item["name"].lower() == normalized_name.lower():
            if item.get("builtin"):
                raise HTTPException(400, "Las reglas predefinidas no se pueden eliminar.")
            deleted = True
            continue
        remaining.append(item)

    if not deleted:
        raise HTTPException(404, "Regla no encontrada.")

    auto_snapshot(f"auth.delete:{normalized_name}", payload)
    write_authentication_rules(remaining)
    return {"ok": True}


@router.post("/authentication-rules/reorder", summary="Reordenar reglas de autenticacion TACACS+")
@router.post("/authentication-rules/reorder/", include_in_schema=False)
def reorder_tacacs_authentication_rules(data: TacacsRulesReorderPayload, payload: dict = Depends(require_admin)):
    ordered_names = [normalize_rule_name(name) for name in data.names]
    name_index = {name.lower(): idx for idx, name in enumerate(ordered_names)}
    items = read_authentication_rules()
    editable = [item for item in items if not item.get("builtin")]
    if set(name_index.keys()) != {item["name"].lower() for item in editable}:
        raise HTTPException(400, "Debes enviar todos los nombres de reglas editables para reordenar.")
    editable.sort(key=lambda item: name_index[item["name"].lower()])
    for idx, item in enumerate(editable, start=1):
        item["priority"] = idx
    builtins = [item for item in items if item.get("builtin")]
    auto_snapshot("auth.reorder", payload)
    write_authentication_rules(builtins + editable)
    return {"ok": True}


@router.get("/device-groups", summary="Listar grupos de dispositivos TACACS+")
@router.get("/device-groups/", include_in_schema=False)
def list_tacacs_device_groups(payload: dict = Depends(require_admin)):
    return read_device_groups()


@router.post("/device-groups", summary="Crear grupo de dispositivos TACACS+")
@router.post("/device-groups/", include_in_schema=False)
def create_tacacs_device_group(data: TacacsDeviceGroupCreate, payload: dict = Depends(require_admin)):
    name = normalize_device_group_name(data.name)
    items = read_device_groups()
    if any(item["name"].lower() == name.lower() for item in items):
        raise HTTPException(400, f"El device group '{name}' ya existe.")

    items.append({
        "name": name,
        "description": (data.description or "").strip() or None,
        "devices": normalize_string_list(data.devices),
    })
    auto_snapshot(f"devicegroup.create:{name}", payload)
    write_device_groups(items)
    return {"ok": True, "name": name}


@router.put("/device-groups/{name}", summary="Actualizar grupo de dispositivos TACACS+")
@router.put("/device-groups/{name}/", include_in_schema=False)
def update_tacacs_device_group(name: str, data: TacacsDeviceGroupUpdate, payload: dict = Depends(require_admin)):
    normalized_name = normalize_device_group_name(name)
    items = read_device_groups()
    updated = False

    for item in items:
        if item["name"].lower() != normalized_name.lower():
            continue
        item["description"] = (data.description or "").strip() or None
        item["devices"] = normalize_string_list(data.devices)
        updated = True
        break

    if not updated:
        raise HTTPException(404, "Device group no encontrado.")

    auto_snapshot(f"devicegroup.update:{normalized_name}", payload)
    write_device_groups(items)
    return {"ok": True, "name": normalized_name}


@router.delete("/device-groups/{name}", summary="Eliminar grupo de dispositivos TACACS+")
@router.delete("/device-groups/{name}/", include_in_schema=False)
def delete_tacacs_device_group(name: str, payload: dict = Depends(require_admin)):
    normalized_name = normalize_device_group_name(name)
    _, _, used_in_authz = get_authorization_usage()
    used_in_auth = get_authentication_device_group_usage()
    if normalized_name.lower() in used_in_authz or normalized_name.lower() in used_in_auth:
        raise HTTPException(400, f"El device group '{normalized_name}' esta en uso por reglas TACACS.")
    items = read_device_groups()
    remaining = [item for item in items if item["name"].lower() != normalized_name.lower()]
    if len(remaining) == len(items):
        raise HTTPException(404, "Device group no encontrado.")

    auto_snapshot(f"devicegroup.delete:{normalized_name}", payload)
    write_device_groups(remaining)
    return {"ok": True}


@router.post("/policy/test", summary="Simular evaluacion TACACS con reglas actuales")
@router.post("/policy/test/", include_in_schema=False)
def test_tacacs_policy(data: TacacsRuleTestPayload, payload: dict = Depends(require_admin)):
    if not str(data.username or "").strip():
        raise HTTPException(400, "username es requerido")
    auth_rule = _evaluate_authentication_rule(data)
    authz_rule = _evaluate_authorization_rule(data)
    return {
        "ok": True,
        "input": {
            "username": data.username,
            "user_groups": normalize_string_list(data.user_groups),
            "device_group": data.device_group,
            "auth_source": data.auth_source,
        },
        "authentication_rule": auth_rule,
        "authorization_rule": authz_rule,
        "result": {
            "auth_source": auth_rule.get("auth_source") if auth_rule else None,
            "shell_profile": authz_rule.get("shell_profile") if authz_rule else None,
            "command_set": authz_rule.get("command_set") if authz_rule else None,
            "matched": bool(auth_rule or authz_rule),
        },
    }


@router.get("/policy/versions", summary="Listar snapshots de politica TACACS")
@router.get("/policy/versions/", include_in_schema=False)
def list_tacacs_policy_versions(payload: dict = Depends(require_admin)):
    return _policy_versions()


@router.get("/policy/versions/{version_id}/redacted", summary="Listar archivos redacted de un snapshot TACACS")
@router.get("/policy/versions/{version_id}/redacted/", include_in_schema=False)
def list_tacacs_policy_version_redacted_files(version_id: str, payload: dict = Depends(require_admin)):
    snapshot = _find_policy_snapshot(version_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot no encontrado.")
    snapshot_dir = Path(POLICY_VERSIONS_DIR) / version_id
    rows = []
    for file_info in snapshot.get("files", []) or []:
        redacted_name = str(file_info.get("redacted_name") or "").strip()
        if not redacted_name:
            continue
        redacted_path = (snapshot_dir / redacted_name).resolve()
        available = redacted_path.exists() and redacted_path.parent == snapshot_dir.resolve()
        rows.append({
            "name": redacted_name,
            "source_name": str(file_info.get("name") or "").strip(),
            "available": available,
        })
    return {
        "version_id": version_id,
        "files": rows,
    }


@router.get("/policy/versions/{version_id}/redacted/{filename}", summary="Descargar archivo redacted de un snapshot TACACS")
@router.get("/policy/versions/{version_id}/redacted/{filename}/", include_in_schema=False)
def get_tacacs_policy_version_redacted_file(version_id: str, filename: str, payload: dict = Depends(require_admin)):
    path = _get_redacted_snapshot_file(version_id, filename)
    if not path:
        raise HTTPException(404, "Archivo redacted no encontrado.")
    content, truncated, total_bytes = _read_text_limited(path)
    if truncated:
        raise HTTPException(
            413,
            f"Archivo redacted demasiado grande ({total_bytes} bytes). Limite: {MAX_REDACTED_READ_BYTES} bytes.",
        )
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


@router.post("/policy/versions/redacted/diff", summary="Comparar dos snapshots redacted TACACS")
@router.post("/policy/versions/redacted/diff/", include_in_schema=False)
def diff_tacacs_policy_redacted(payload_data: TacacsPolicyDiffPayload, payload: dict = Depends(require_admin)):
    started_at = time.perf_counter()
    from_id = str(payload_data.from_version_id or "").strip()
    to_id = str(payload_data.to_version_id or "").strip()
    filename = str(payload_data.filename or "").strip()
    max_diff_lines = int(payload_data.max_diff_lines)
    max_files = int(payload_data.max_files)
    sort_by = str(payload_data.sort_by or "name").strip().lower()
    include_diff = bool(payload_data.include_diff)
    only_changed = bool(payload_data.only_changed)
    if not from_id or not to_id:
        raise HTTPException(400, "from_version_id y to_version_id son requeridos.")
    if sort_by not in {"name", "changes_desc"}:
        raise HTTPException(400, "sort_by debe ser 'name' o 'changes_desc'.")

    if not _find_policy_snapshot(from_id):
        raise HTTPException(404, f"Snapshot origen '{from_id}' no encontrado.")
    if not _find_policy_snapshot(to_id):
        raise HTTPException(404, f"Snapshot destino '{to_id}' no encontrado.")

    if filename:
        requested_files = [filename]
    else:
        requested_files = sorted(_snapshot_redacted_names(from_id).union(_snapshot_redacted_names(to_id)))
        if not requested_files:
            raise HTTPException(404, "No hay archivos redacted para comparar entre esos snapshots.")

    requested_total = len(requested_files)
    truncated_files = requested_total > max_files
    if truncated_files:
        requested_files = requested_files[:max_files]

    file_diffs = []
    for current_name in requested_files:
        from_path = _get_redacted_snapshot_file(from_id, current_name)
        to_path = _get_redacted_snapshot_file(to_id, current_name)

        from_exists = bool(from_path)
        to_exists = bool(to_path)
        if not from_exists and not to_exists:
            continue

        from_lines = []
        to_lines = []
        from_read_truncated = False
        to_read_truncated = False
        from_total_bytes = 0
        to_total_bytes = 0
        if from_path:
            from_text, from_read_truncated, from_total_bytes = _read_text_limited(from_path)
            from_lines = from_text.splitlines()
        if to_path:
            to_text, to_read_truncated, to_total_bytes = _read_text_limited(to_path)
            to_lines = to_text.splitlines()

        diff_lines = list(difflib.unified_diff(
            from_lines,
            to_lines,
            fromfile=f"{from_id}/{current_name}",
            tofile=f"{to_id}/{current_name}",
            lineterm="",
        ))
        truncated = False
        omitted_lines = 0
        if len(diff_lines) > max_diff_lines:
            truncated = True
            omitted_lines = len(diff_lines) - max_diff_lines
            diff_lines = diff_lines[:max_diff_lines]
        item = {
            "filename": current_name,
            "from_exists": from_exists,
            "to_exists": to_exists,
            "from_total_bytes": from_total_bytes,
            "to_total_bytes": to_total_bytes,
            "from_read_truncated": from_read_truncated,
            "to_read_truncated": to_read_truncated,
            "has_changes": len(diff_lines) > 0,
            "change_lines": len(diff_lines),
            "truncated": truncated,
            "omitted_lines": omitted_lines,
        }
        if include_diff:
            item["diff"] = "\n".join(diff_lines)
        file_diffs.append(item)

    if sort_by == "changes_desc":
        file_diffs.sort(key=lambda item: (int(item.get("change_lines", 0)), str(item.get("filename", "")).lower()), reverse=True)
    else:
        file_diffs.sort(key=lambda item: str(item.get("filename", "")).lower())

    changed_files = [item for item in file_diffs if item.get("has_changes")]
    output_files = changed_files if only_changed else file_diffs
    returned_changed_files = sum(1 for item in output_files if item.get("has_changes"))
    processing_ms = int((time.perf_counter() - started_at) * 1000)
    return {
        "ok": True,
        "from_version_id": from_id,
        "to_version_id": to_id,
        "filename": filename or None,
        "max_diff_lines": max_diff_lines,
        "max_files": max_files,
        "sort_by": sort_by,
        "include_diff": include_diff,
        "only_changed": only_changed,
        "requested_files": requested_total,
        "truncated_files": truncated_files,
        "scanned_files": len(file_diffs),
        "has_changes": len(changed_files) > 0,
        "total_files": len(output_files),
        "changed_files": len(changed_files),
        "returned_changed_files": returned_changed_files,
        "processing_ms": processing_ms,
        "files": output_files,
    }


def apply_rendered_tacacs_policy(actor: str, restart_service: bool = True, strict_backup: bool = True) -> dict:
    main_cfg_path = Path(TACACS_CFG)
    managed_cfg_path = Path(TACACS_MANAGED_CFG)

    main_cfg_path.parent.mkdir(parents=True, exist_ok=True)
    managed_cfg_path.parent.mkdir(parents=True, exist_ok=True)

    old_main = main_cfg_path.read_text(encoding="utf-8", errors="replace") if main_cfg_path.exists() else ""
    old_managed = managed_cfg_path.read_text(encoding="utf-8", errors="replace") if managed_cfg_path.exists() else ""

    managed_content = render_managed_tacacs_policy_cfg()
    new_main = ensure_main_cfg_includes_managed(old_main)

    if strict_backup:
        create_policy_snapshot("Pre render/apply TACACS policy", actor)

    atomic_write_text(managed_cfg_path, managed_content, encoding="utf-8")
    ensure_restrictive_permissions(managed_cfg_path)
    if new_main != old_main:
        atomic_write_text(main_cfg_path, new_main, encoding="utf-8")
        ensure_restrictive_permissions(main_cfg_path)

    if restart_service:
        result = run_systemctl("restart", TACACS_SVC, timeout=20)
        if result.returncode != 0:
            # Rollback if service failed after apply.
            atomic_write_text(managed_cfg_path, old_managed, encoding="utf-8")
            ensure_restrictive_permissions(managed_cfg_path)
            atomic_write_text(main_cfg_path, old_main, encoding="utf-8")
            ensure_restrictive_permissions(main_cfg_path)
            rollback = run_systemctl("restart", TACACS_SVC, timeout=20)
            rollback_detail = (rollback.stderr or rollback.stdout or "").strip()
            detail = (result.stderr or result.stdout or "Fallo al reiniciar TACACS.").strip()
            raise HTTPException(
                500,
                "Error aplicando policy renderizada. Se hizo rollback. "
                f"Detalle: {detail}. Rollback: {rollback_detail or 'ok'}",
            )

    return {
        "ok": True,
        "main_cfg": str(main_cfg_path),
        "managed_cfg": str(managed_cfg_path),
        "managed_bytes": len(managed_content.encode("utf-8")),
        "main_cfg_updated": new_main != old_main,
        "service_restarted": restart_service,
    }


@router.post("/policy/versions", summary="Crear snapshot de politica TACACS")
@router.post("/policy/versions/", include_in_schema=False)
def create_tacacs_policy_version(data: TacacsPolicySnapshotCreate, payload: dict = Depends(require_admin)):
    actor = str(payload.get("sub") or payload.get("username") or "admin")
    return create_policy_snapshot(data.note, actor)


@router.get("/policy/render", summary="Renderizar cfg TACACS administrado sin aplicar")
@router.get("/policy/render/", include_in_schema=False)
def render_tacacs_policy(payload: dict = Depends(require_admin)):
    content = render_managed_tacacs_policy_cfg()
    return {
        "ok": True,
        "managed_cfg": TACACS_MANAGED_CFG,
        "bytes": len(content.encode("utf-8")),
        "content": content,
    }


@router.post("/policy/render-apply", summary="Renderizar y aplicar cfg TACACS administrado con rollback")
@router.post("/policy/render-apply/", include_in_schema=False)
def render_apply_tacacs_policy(data: TacacsPolicyRenderApplyPayload, payload: dict = Depends(require_admin)):
    actor = str(payload.get("sub") or payload.get("username") or "admin")
    auto_snapshot("policy.render-apply", payload)
    return apply_rendered_tacacs_policy(
        actor=actor,
        restart_service=bool(data.restart_service),
        strict_backup=bool(data.strict_backup),
    )


@router.post("/policy/versions/{version_id}/rollback", summary="Rollback de politica TACACS")
@router.post("/policy/versions/{version_id}/rollback/", include_in_schema=False)
def rollback_tacacs_policy_version(version_id: str, payload: dict = Depends(require_admin)):
    started_at = time.perf_counter()
    snapshot = _find_policy_snapshot(version_id)
    if not snapshot:
        raise HTTPException(404, "Snapshot no encontrado.")
    snapshot_dir = Path(POLICY_VERSIONS_DIR) / version_id
    if not snapshot_dir.exists():
        raise HTTPException(404, "Directorio del snapshot no encontrado.")
    actor = str(payload.get("sub") or payload.get("username") or "admin")
    pre_snapshot = create_policy_snapshot(f"Pre-rollback {version_id}", actor)
    tracked_targets = _tracked_policy_targets()
    restored_files = 0
    deleted_files = 0
    skipped_files = 0
    details = []

    for file_info in snapshot.get("files", []):
        name = str(file_info.get("name") or "").strip()
        exists = bool(file_info.get("exists"))
        raw_path = str(file_info.get("path") or "").strip()
        row = {
            "name": name or None,
            "path": raw_path or None,
            "expected_exists": exists,
        }

        if not raw_path:
            row["status"] = "skipped"
            row["reason"] = "missing_path"
            skipped_files += 1
            details.append(row)
            continue
        try:
            resolved = Path(raw_path).resolve()
        except Exception:
            row["status"] = "skipped"
            row["reason"] = "invalid_path"
            skipped_files += 1
            details.append(row)
            continue
        target = tracked_targets.get(str(resolved))
        if not target:
            # Ignoramos rutas fuera de POLICY_TRACKED_FILES para evitar rollback inseguro.
            row["status"] = "skipped"
            row["reason"] = "outside_tracked_files"
            skipped_files += 1
            details.append(row)
            continue

        # El nombre en metadata debe coincidir con el basename esperado del archivo tracked.
        if name != target.name:
            row["status"] = "skipped"
            row["reason"] = "name_mismatch"
            row["target"] = str(target)
            skipped_files += 1
            details.append(row)
            continue
        # Evita traversal y fuerza que la fuente viva dentro del directorio del snapshot.
        source = (snapshot_dir / name).resolve()
        if source.parent != snapshot_dir.resolve():
            row["status"] = "skipped"
            row["reason"] = "invalid_source_parent"
            row["target"] = str(target)
            skipped_files += 1
            details.append(row)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        if exists and source.exists():
            shutil.copy2(source, target)
            ensure_restrictive_permissions(target)
            row["status"] = "restored"
            row["target"] = str(target)
            restored_files += 1
        elif target.exists():
            target.unlink()
            row["status"] = "deleted"
            row["target"] = str(target)
            deleted_files += 1
        else:
            row["status"] = "skipped"
            row["reason"] = "source_missing_and_target_absent"
            row["target"] = str(target)
            skipped_files += 1
        details.append(row)
    processing_ms = int((time.perf_counter() - started_at) * 1000)
    return {
        "ok": True,
        "message": f"Rollback aplicado desde snapshot {version_id}",
        "version_id": version_id,
        "pre_rollback_snapshot_id": str(pre_snapshot.get("id") or ""),
        "restored_files": restored_files,
        "deleted_files": deleted_files,
        "skipped_files": skipped_files,
        "processing_ms": processing_ms,
        "details": details,
    }


@router.post("/reload", summary="Recargar tac_plus-ng tras cambios en config")
@router.post("/reload/", include_in_schema=False)
def reload_tacacs(payload: dict = Depends(require_admin)):
    try:
        result = run_systemctl("restart", TACACS_SVC, timeout=15)
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "Fallo desconocido al reiniciar TACACS.").strip()
            raise HTTPException(500, f"Error al recargar: {detail}")
        return {"ok": True, "message": "tac_plus-ng recargado correctamente."}
    except subprocess.TimeoutExpired:
        raise HTTPException(500, "Timeout al recargar el servicio.")


@router.get("/status", summary="Estado del servicio TACACS+")
@router.get("/status/", include_in_schema=False)
def tacacs_status(payload: dict = Depends(require_admin)):
    try:
        ensure_predefined_shell_profiles()
        result = run_systemctl("is-active", TACACS_SVC, timeout=5)
        active = result.stdout.strip() == "active"
        auth_count = len(read_log(ACCESS_LOG, 10000))
        cmd_count = len(read_log(ACCOUNTING_LOG, 10000))
        return {
            "active": active,
            "service": TACACS_SVC,
            "port": 49,
            "auth_log_lines": auth_count,
            "cmd_log_lines": cmd_count,
            "local_users": len(get_local_users_from_cfg(include_password=False)),
            "profiles": len(get_profiles_from_cfg()),
            "command_sets": len(read_command_sets()),
            "authorization_rules": len(read_authorization_rules()),
            "authentication_rules": len(read_authentication_rules()),
            "device_groups": len(read_device_groups()),
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))
