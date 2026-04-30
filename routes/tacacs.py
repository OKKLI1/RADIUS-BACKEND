"""
routes/tacacs.py
Gestión de TACACS+: logs, usuarios locales y perfiles.
Solo accesible por admin.
"""
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core.security import require_admin
from core.database import query, execute

router = APIRouter(prefix="/api/tacacs", tags=["TACACS+"])

TACACS_CFG    = "/usr/local/etc/tac_plus-ng/tac_plus-ng.cfg"
ACCESS_LOG    = "/var/log/tac_plus-ng/access.log"
ACCOUNTING_LOG= "/var/log/tac_plus-ng/accounting.log"
TACACS_SVC    = "tac_plus-ng"

# ── Parsers de log ─────────────────────────────────────────────────────────────

def parse_access_log(lines: list[str]) -> list[dict]:
    """
    Formato: 2026-04-28 12:26:52 -0400 127.0.0.1  jdiaz  python_tty0  python_device  shell login succeeded
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
            tz       = parts[2]
            ip       = parts[3]
            user     = parts[4]
            tty      = parts[5]
            device   = parts[6]
            action   = ' '.join(parts[7:]) if len(parts) > 7 else ''
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
    Formato típico: 2026-04-28 12:30:00 -0400 IP USER TTY DEVICE start/stop cmd
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


# ── Endpoints de logs ──────────────────────────────────────────────────────────

@router.get("/auth-logs", summary="Logs de autenticación TACACS+")
@router.get("/auth-logs/", include_in_schema=False)
def get_auth_logs(limit: int = 200, payload: dict = Depends(require_admin)):
    lines = read_log(ACCESS_LOG, limit)
    parsed = parse_access_log(lines)
    parsed.reverse()
    return {"total": len(parsed), "logs": parsed}


@router.get("/cmd-logs", summary="Logs de comandos TACACS+")
@router.get("/cmd-logs/", include_in_schema=False)
def get_cmd_logs(limit: int = 200, payload: dict = Depends(require_admin)):
    lines = read_log(ACCOUNTING_LOG, limit)
    parsed = parse_accounting_log(lines)
    parsed.reverse()
    return {"total": len(parsed), "logs": parsed}


# ── Parsear config para usuarios y perfiles ────────────────────────────────────

def read_cfg() -> str:
    return Path(TACACS_CFG).read_text(errors="replace")


def get_local_users_from_cfg() -> list[dict]:
    """Extrae usuarios locales (user ... { password login = clear ... }) del config."""
    cfg = read_cfg()
    users = []
    pattern = re.compile(
        r'user\s+(\S+)\s*\{([^}]*)\}',
        re.DOTALL
    )
    for m in pattern.finditer(cfg):
        name = m.group(1)
        body = m.group(2)
        pw_match = re.search(r'password\s+login\s*=\s*clear\s+(\S+)', body)
        profile_match = re.search(r'profile\s*=\s*(\S+)', body)
        users.append({
            "username": name,
            "password": pw_match.group(1) if pw_match else "***",
            "profile": profile_match.group(1) if profile_match else None,
            "is_local": True,
        })
    return users


def get_profiles_from_cfg() -> list[dict]:
    """Extrae perfiles del config."""
    cfg = read_cfg()
    profiles = []
    pattern = re.compile(
        r'profile\s+(\S+)\s*\{(.*?)\n\s*\}',
        re.DOTALL
    )
    for m in pattern.finditer(cfg):
        name = m.group(1)
        body = m.group(2)
        priv_match = re.search(r'set priv-lvl\s*=\s*(\d+)', body)
        profiles.append({
            "name": name,
            "priv_level": int(priv_match.group(1)) if priv_match else 0,
            "script": body.strip(),
        })
    return profiles


# ── Endpoints usuarios locales ─────────────────────────────────────────────────

@router.get("/users", summary="Listar usuarios locales TACACS+")
@router.get("/users/", include_in_schema=False)
def list_tacacs_users(payload: dict = Depends(require_admin)):
    return get_local_users_from_cfg()


class TacacsUserCreate(BaseModel):
    username: str
    password: str
    profile: str


class TacacsUserUpdate(BaseModel):
    password: Optional[str] = None
    profile: Optional[str] = None


def write_user_to_cfg(username: str, password: str, profile: str):
    cfg = read_cfg()
    user_block = f'\n    user {username} {{\n        password login = clear {password}\n        profile = {profile}\n    }}\n'
    # Insertar antes del último } del bloque id = tac_plus-ng
    cfg = cfg.rstrip()
    if cfg.endswith('}'):
        cfg = cfg[:-1] + user_block + '}\n'
    Path(TACACS_CFG).write_text(cfg)


def remove_user_from_cfg(username: str):
    cfg = read_cfg()
    pattern = re.compile(
        r'\n\s*user\s+' + re.escape(username) + r'\s*\{[^}]*\}',
        re.DOTALL
    )
    cfg = pattern.sub('', cfg)
    Path(TACACS_CFG).write_text(cfg)


@router.post("/users", summary="Crear usuario local TACACS+")
@router.post("/users/", include_in_schema=False)
def create_tacacs_user(data: TacacsUserCreate, payload: dict = Depends(require_admin)):
    if not data.username.strip():
        raise HTTPException(400, "Username requerido.")
    existing = get_local_users_from_cfg()
    if any(u["username"] == data.username for u in existing):
        raise HTTPException(400, f"Usuario '{data.username}' ya existe.")
    write_user_to_cfg(data.username, data.password, data.profile)
    return {"ok": True, "username": data.username}


@router.put("/users/{username}", summary="Actualizar usuario local TACACS+")
def update_tacacs_user(username: str, data: TacacsUserUpdate,
                       payload: dict = Depends(require_admin)):
    existing = get_local_users_from_cfg()
    user = next((u for u in existing if u["username"] == username), None)
    if not user:
        raise HTTPException(404, "Usuario no encontrado.")
    new_pw = data.password or user["password"]
    new_profile = data.profile or user["profile"]
    remove_user_from_cfg(username)
    write_user_to_cfg(username, new_pw, new_profile)
    return {"ok": True}


@router.delete("/users/{username}", summary="Eliminar usuario local TACACS+")
def delete_tacacs_user(username: str, payload: dict = Depends(require_admin)):
    remove_user_from_cfg(username)
    return {"ok": True}


# ── Endpoints perfiles ─────────────────────────────────────────────────────────

@router.get("/profiles", summary="Listar perfiles TACACS+")
@router.get("/profiles/", include_in_schema=False)
def list_tacacs_profiles(payload: dict = Depends(require_admin)):
    return get_profiles_from_cfg()


# ── Reload ─────────────────────────────────────────────────────────────────────

@router.post("/reload", summary="Recargar tac_plus-ng tras cambios en config")
@router.post("/reload/", include_in_schema=False)
def reload_tacacs(payload: dict = Depends(require_admin)):
    try:
        result = subprocess.run(
            ["systemctl", "restart", TACACS_SVC],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            raise HTTPException(500, f"Error al recargar: {result.stderr}")
        return {"ok": True, "message": "tac_plus-ng recargado correctamente."}
    except subprocess.TimeoutExpired:
        raise HTTPException(500, "Timeout al recargar el servicio.")


# ── Status ─────────────────────────────────────────────────────────────────────

@router.get("/status", summary="Estado del servicio TACACS+")
@router.get("/status/", include_in_schema=False)
def tacacs_status(payload: dict = Depends(require_admin)):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", TACACS_SVC],
            capture_output=True, text=True, timeout=5
        )
        active = result.stdout.strip() == "active"
        # Contar líneas de logs
        auth_count  = len(read_log(ACCESS_LOG, 10000))
        cmd_count   = len(read_log(ACCOUNTING_LOG, 10000))
        return {
            "active": active,
            "service": TACACS_SVC,
            "port": 49,
            "auth_log_lines": auth_count,
            "cmd_log_lines": cmd_count,
            "local_users": len(get_local_users_from_cfg()),
            "profiles": len(get_profiles_from_cfg()),
        }
    except Exception as e:
        raise HTTPException(500, str(e))
