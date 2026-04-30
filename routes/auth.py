import subprocess
import hashlib
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends
from pydantic import BaseModel
from typing import Optional
from core.config import settings
from core.security import create_access_token, require_admin, require_helpdesk
from core.database import query, execute

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])

# ── Grupos AD → roles (en minúsculas, como los devuelve wbinfo) ───────────────
# wbinfo normaliza: "AxioRadius-Admins" → "axioradius-admins"
# Orden de mayor a menor privilegio
AD_ROLE_GROUPS = [
    ("admin",    "axioradius-admins"),
    ("config",   "axioradius-config"),
    ("helpdesk", "axioradius-helpdesk"),
]
AD_DOMAIN = "AXIO"


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def audit_log(username, action, role=None, target=None, detail=None, ip=None, user_agent=None):
    try:
        execute(
            """INSERT INTO axio_audit_log
               (username, role, action, target, detail, ip_address, user_agent, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (username, role, action, target,
             json.dumps(detail) if detail else None,
             ip, user_agent, datetime.utcnow())
        )
    except Exception:
        pass


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def authenticate_ad(username: str, password: str) -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/ntlm_auth", "--request-nt-key",
             f"--domain={AD_DOMAIN}",
             f"--username={username}",
             f"--password={password}"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_ad_groups(username: str) -> list:
    """
    Obtiene grupos del usuario resolviendo GIDs via wbinfo.
    
    wbinfo --user-groups devuelve GIDs numéricos.
    wbinfo --gid-info=GID devuelve: nombre_grupo:x:GID:
    
    Retorna lista de nombres en minúsculas para comparación segura.
    Ej: ["axioradius-admins", "usuarios del dominio", "builtin\\users"]
    """
    try:
        # Paso 1: obtener GIDs del usuario
        result = subprocess.run(
            ["/usr/bin/wbinfo", f"--user-groups={AD_DOMAIN}\\{username}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return []

        gids = [line.strip() for line in result.stdout.strip().splitlines() if line.strip()]
        if not gids:
            return []

        # Paso 2: resolver cada GID a nombre de grupo
        groups = []
        for gid in gids:
            try:
                r = subprocess.run(
                    ["/usr/bin/wbinfo", f"--gid-info={gid}"],
                    capture_output=True, text=True, timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip():
                    # Formato: "nombre_grupo:x:GID:" o "DOMINIO\nombre:x:GID:"
                    group_name = r.stdout.strip().split(":")[0]
                    # Quitar prefijo de dominio si viene (BUILTIN\users → users)
                    if "\\" in group_name:
                        group_name = group_name.split("\\", 1)[1]
                    groups.append(group_name.lower().strip())
            except Exception:
                continue

        return groups
    except Exception:
        return []


def resolve_ad_role(username: str):
    """
    Devuelve el rol según grupo AD en minúsculas.
    None = acceso denegado.
    """
    groups = get_ad_groups(username)
    for role, group_name in AD_ROLE_GROUPS:
        if group_name in groups:
            return role
    return None


def get_operator(username: str):
    return query(
        "SELECT * FROM axio_operators WHERE username = %s AND active = 1",
        (username,), fetchone=True
    )


def upsert_ad_operator(username: str, role: str):
    existing = query("SELECT id FROM axio_operators WHERE username = %s",
                     (username,), fetchone=True)
    if existing:
        execute("UPDATE axio_operators SET role = %s, last_login = %s WHERE username = %s",
                (role, datetime.utcnow(), username))
    else:
        execute(
            """INSERT INTO axio_operators
               (username, password_hash, role, auth_method, active, created_at, last_login)
               VALUES (%s, NULL, %s, 'active_directory', 1, %s, %s)""",
            (username, role, datetime.utcnow(), datetime.utcnow())
        )


def _update_last_login(username: str):
    try:
        execute("UPDATE axio_operators SET last_login = %s WHERE username = %s",
                (datetime.utcnow(), username))
    except Exception:
        pass


@router.post("/login", summary="Login del panel de administración")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username.strip()
    password = form_data.password
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")[:200]

    # 1. Admin .env
    if username == settings.GUI_ADMIN_USER and password == settings.GUI_ADMIN_PASSWORD:
        token = create_access_token({"sub": username, "role": "admin", "auth_method": "env"})
        audit_log(username, "login_ok", "admin", ip=ip, user_agent=ua, detail={"method": "env"})
        _update_last_login(username)
        return {"access_token": token, "token_type": "bearer", "role": "admin"}

    # 2. Operador local
    op = get_operator(username)
    if op and op.get("auth_method") == "local" and op.get("password_hash"):
        if op["password_hash"] == hash_password(password):
            token = create_access_token({"sub": username, "role": op["role"], "auth_method": "local"})
            audit_log(username, "login_ok", op["role"], ip=ip, user_agent=ua, detail={"method": "local"})
            _update_last_login(username)
            return {"access_token": token, "token_type": "bearer", "role": op["role"]}
        audit_log(username, "login_fail", ip=ip, user_agent=ua,
                  detail={"method": "local", "reason": "wrong_password"})
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    # 3. Active Directory
    if not authenticate_ad(username, password):
        audit_log(username, "login_fail", ip=ip, user_agent=ua, detail={"reason": "invalid_credentials"})
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")

    role = resolve_ad_role(username)
    if role is None:
        audit_log(username, "login_fail", ip=ip, user_agent=ua,
                  detail={"method": "active_directory", "reason": "no_axioradius_group"})
        raise HTTPException(
            status_code=403,
            detail=(
                "Acceso denegado. Tu usuario no pertenece a ningún grupo AxioRadius. "
                "Contacta al administrador para agregarte a AxioRadius-Admins, "
                "AxioRadius-Config o AxioRadius-Helpdesk en Active Directory."
            ),
        )

    upsert_ad_operator(username, role)
    token = create_access_token({"sub": username, "role": role, "auth_method": "active_directory"})
    audit_log(username, "login_ok", role, ip=ip, user_agent=ua,
              detail={"method": "active_directory", "group": f"axioradius-{role}"})
    return {"access_token": token, "token_type": "bearer", "role": role}


@router.get("/me")
def me(payload: dict = Depends(require_helpdesk)):
    return {"username": payload.get("sub"), "role": payload.get("role"),
            "auth_method": payload.get("auth_method", "local")}


class OperatorCreate(BaseModel):
    username: str
    password: str
    full_name: Optional[str] = ""
    email: Optional[str] = ""
    role: str = "helpdesk"


class OperatorUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None


@router.get("/operators")
def list_operators(payload: dict = Depends(require_admin)):
    return query("""SELECT id, username, full_name, email, role, auth_method,
                           active, created_at, last_login
                    FROM axio_operators ORDER BY created_at DESC""")


@router.post("/operators")
def create_operator(data: OperatorCreate, request: Request,
                    payload: dict = Depends(require_admin)):
    if data.role not in ("admin", "config", "helpdesk"):
        raise HTTPException(400, "Rol inválido. Usa: admin, config, helpdesk")
    if get_operator(data.username):
        raise HTTPException(400, f"El operador '{data.username}' ya existe")
    execute(
        """INSERT INTO axio_operators
           (username, password_hash, full_name, email, role, auth_method, active, created_at)
           VALUES (%s, %s, %s, %s, %s, 'local', 1, %s)""",
        (data.username, hash_password(data.password),
         data.full_name, data.email, data.role, datetime.utcnow())
    )
    audit_log(payload["sub"], "create_operator", payload.get("role"),
              target=f"operator:{data.username}", ip=get_client_ip(request),
              detail={"role": data.role})
    return {"ok": True, "username": data.username, "role": data.role}


@router.put("/operators/{op_id}")
def update_operator(op_id: int, data: OperatorUpdate, request: Request,
                    payload: dict = Depends(require_admin)):
    fields, values = [], []
    if data.full_name is not None: fields.append("full_name = %s"); values.append(data.full_name)
    if data.email is not None: fields.append("email = %s"); values.append(data.email)
    if data.role is not None:
        if data.role not in ("admin", "config", "helpdesk"):
            raise HTTPException(400, "Rol inválido")
        fields.append("role = %s"); values.append(data.role)
    if data.active is not None: fields.append("active = %s"); values.append(int(data.active))
    if data.password: fields.append("password_hash = %s"); values.append(hash_password(data.password))
    if not fields: raise HTTPException(400, "Nada que actualizar")
    values.append(op_id)
    execute(f"UPDATE axio_operators SET {', '.join(fields)} WHERE id = %s", tuple(values))
    audit_log(payload["sub"], "update_operator", payload.get("role"),
              target=f"operator_id:{op_id}", ip=get_client_ip(request))
    return {"ok": True}


@router.delete("/operators/{op_id}")
def delete_operator(op_id: int, request: Request, payload: dict = Depends(require_admin)):
    execute("DELETE FROM axio_operators WHERE id = %s", (op_id,))
    audit_log(payload["sub"], "delete_operator", payload.get("role"),
              target=f"operator_id:{op_id}", ip=get_client_ip(request))
    return {"ok": True}


@router.get("/audit-log")
def get_audit_log(limit: int = 200, username: str = None, action: str = None,
                  payload: dict = Depends(require_admin)):
    conditions, params = [], []
    if username: conditions.append("username = %s"); params.append(username)
    if action: conditions.append("action = %s"); params.append(action)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.append(limit)
    return query(
        f"""SELECT id, username, role, action, target, detail,
                   ip_address, user_agent, created_at
            FROM axio_audit_log {where}
            ORDER BY created_at DESC LIMIT %s""",
        tuple(params)
    )
