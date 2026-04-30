"""
routes/nas.py
CRUD de NAS con grupos jerárquicos + soporte RADIUS/TACACS.
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from core.security import require_admin, require_config, require_helpdesk
from core.database import query, execute

router = APIRouter(prefix="/api/nas", tags=["NAS"])


# ── Modelos ────────────────────────────────────────────────────────────────────

DEVICE_SERIES = [
    "Cisco Catalyst", "Cisco IOS", "Cisco ASA",
    "Huawei Engine", "Huawei S-Series", "Huawei AR",
    "Mikrotik RouterOS", "Ubiquiti UniFi", "Ubiquiti EdgeOS",
    "Juniper", "Aruba", "FortiGate", "other"
]

class NasCreate(BaseModel):
    nasname:        str
    shortname:      Optional[str] = ""
    type:           Optional[str] = "other"
    ports:          Optional[int] = None
    secret:         str
    server:         Optional[str] = ""
    community:      Optional[str] = ""
    description:    Optional[str] = "RADIUS Client"
    group_id:       Optional[int] = None
    device_series:  Optional[str] = "other"
    radius_enabled: Optional[bool] = True
    tacacs_enabled: Optional[bool] = False
    tacacs_secret:  Optional[str] = None
    location:       Optional[str] = ""

class NasUpdate(BaseModel):
    nasname:        Optional[str] = None
    shortname:      Optional[str] = None
    type:           Optional[str] = None
    ports:          Optional[int] = None
    secret:         Optional[str] = None
    server:         Optional[str] = None
    community:      Optional[str] = None
    description:    Optional[str] = None
    group_id:       Optional[int] = None
    device_series:  Optional[str] = None
    radius_enabled: Optional[bool] = None
    tacacs_enabled: Optional[bool] = None
    tacacs_secret:  Optional[str] = None
    location:       Optional[str] = None

class NasGroupCreate(BaseModel):
    name:        str
    parent_id:   Optional[int] = None
    description: Optional[str] = ""

class NasGroupUpdate(BaseModel):
    name:        Optional[str] = None
    description: Optional[str] = None


# ── Grupos de NAS ──────────────────────────────────────────────────────────────

@router.get("/groups", summary="Listar grupos de NAS (árbol completo)")
@router.get("/groups/", include_in_schema=False)
def list_nas_groups(payload: dict = Depends(require_helpdesk)):
    rows = query(
        """SELECT
               g.id, g.name, g.parent_id, g.description, g.created_by, g.created_at,
               COUNT(n.id) AS nas_count
           FROM axio_nas_groups g
           LEFT JOIN nas n ON n.group_id = g.id
           GROUP BY g.id
           ORDER BY g.parent_id IS NULL DESC, g.name ASC"""
    )
    return rows


@router.post("/groups", summary="Crear grupo de NAS")
@router.post("/groups/", include_in_schema=False)
def create_nas_group(data: NasGroupCreate, payload: dict = Depends(require_admin)):
    if not data.name.strip():
        raise HTTPException(400, "El nombre no puede estar vacío.")
    if data.parent_id:
        parent = query("SELECT id FROM axio_nas_groups WHERE id = %s",
                       (data.parent_id,), fetchone=True)
        if not parent:
            raise HTTPException(404, "Grupo padre no encontrado.")
    gid = execute(
        "INSERT INTO axio_nas_groups (name, parent_id, description, created_by, created_at) VALUES (%s, %s, %s, %s, %s)",
        (data.name.strip(), data.parent_id, data.description, payload.get("sub"), datetime.utcnow())
    )
    return {"ok": True, "id": gid, "name": data.name.strip()}


@router.put("/groups/{group_id}", summary="Actualizar grupo de NAS")
def update_nas_group(group_id: int, data: NasGroupUpdate,
                     payload: dict = Depends(require_admin)):
    fields, values = [], []
    if data.name is not None:
        fields.append("name = %s"); values.append(data.name.strip())
    if data.description is not None:
        fields.append("description = %s"); values.append(data.description)
    if not fields:
        raise HTTPException(400, "Nada que actualizar.")
    values.append(group_id)
    execute(f"UPDATE axio_nas_groups SET {', '.join(fields)} WHERE id = %s", tuple(values))
    return {"ok": True}


@router.delete("/groups/{group_id}", summary="Eliminar grupo de NAS")
def delete_nas_group(group_id: int, payload: dict = Depends(require_admin)):
    # Los NAS del grupo quedan sin grupo (SET NULL por FK)
    execute("DELETE FROM axio_nas_groups WHERE id = %s", (group_id,))
    return {"ok": True}


# ── NAS ────────────────────────────────────────────────────────────────────────

@router.get("", summary="Listar NAS")
@router.get("/", include_in_schema=False)
def list_nas(group_id: int = None, payload: dict = Depends(require_helpdesk)):
    if group_id is not None:
        rows = query(
            """SELECT n.*, g.name AS group_name
               FROM nas n
               LEFT JOIN axio_nas_groups g ON g.id = n.group_id
               WHERE n.group_id = %s
               ORDER BY n.shortname""",
            (group_id,)
        )
    else:
        rows = query(
            """SELECT n.*, g.name AS group_name
               FROM nas n
               LEFT JOIN axio_nas_groups g ON g.id = n.group_id
               ORDER BY n.shortname"""
        )
    return rows


@router.get("/{nas_id}", summary="Obtener NAS por ID")
def get_nas(nas_id: int, payload: dict = Depends(require_helpdesk)):
    row = query(
        """SELECT n.*, g.name AS group_name
           FROM nas n
           LEFT JOIN axio_nas_groups g ON g.id = n.group_id
           WHERE n.id = %s""",
        (nas_id,), fetchone=True
    )
    if not row:
        raise HTTPException(404, "NAS no encontrado.")
    return row


@router.post("", summary="Crear NAS")
@router.post("/", include_in_schema=False)
def create_nas(data: NasCreate, payload: dict = Depends(require_admin)):
    existing = query("SELECT id FROM nas WHERE nasname = %s", (data.nasname,), fetchone=True)
    if existing:
        raise HTTPException(400, f"Ya existe un NAS con IP {data.nasname}")
    nas_id = execute(
        """INSERT INTO nas
           (nasname, shortname, type, ports, secret, server, community, description,
            group_id, device_series, radius_enabled, tacacs_enabled, tacacs_secret,
            location, created_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (data.nasname, data.shortname, data.type, data.ports, data.secret,
         data.server, data.community, data.description,
         data.group_id, data.device_series,
         int(data.radius_enabled), int(data.tacacs_enabled),
         data.tacacs_secret, data.location, datetime.utcnow())
    )
    return {"ok": True, "id": nas_id, "nasname": data.nasname}


@router.put("/{nas_id}", summary="Actualizar NAS")
def update_nas(nas_id: int, data: NasUpdate, payload: dict = Depends(require_admin)):
    existing = query("SELECT id FROM nas WHERE id = %s", (nas_id,), fetchone=True)
    if not existing:
        raise HTTPException(404, "NAS no encontrado.")
    fields, values = [], []
    mapping = {
        "nasname": data.nasname, "shortname": data.shortname,
        "type": data.type, "ports": data.ports, "secret": data.secret,
        "server": data.server, "community": data.community,
        "description": data.description, "group_id": data.group_id,
        "device_series": data.device_series, "location": data.location,
        "tacacs_secret": data.tacacs_secret,
    }
    for col, val in mapping.items():
        if val is not None:
            fields.append(f"{col} = %s"); values.append(val)
    if data.radius_enabled is not None:
        fields.append("radius_enabled = %s"); values.append(int(data.radius_enabled))
    if data.tacacs_enabled is not None:
        fields.append("tacacs_enabled = %s"); values.append(int(data.tacacs_enabled))
    if not fields:
        raise HTTPException(400, "Nada que actualizar.")
    values.append(nas_id)
    execute(f"UPDATE nas SET {', '.join(fields)} WHERE id = %s", tuple(values))
    return {"ok": True}


@router.delete("/{nas_id}", summary="Eliminar NAS")
def delete_nas(nas_id: int, payload: dict = Depends(require_admin)):
    existing = query("SELECT id FROM nas WHERE id = %s", (nas_id,), fetchone=True)
    if not existing:
        raise HTTPException(404, "NAS no encontrado.")
    execute("DELETE FROM nas WHERE id = %s", (nas_id,))
    return {"ok": True}


# ── Device series disponibles ──────────────────────────────────────────────────

@router.get("/meta/device-series", summary="Listar marcas/series disponibles")
def get_device_series(payload: dict = Depends(require_helpdesk)):
    return {"device_series": DEVICE_SERIES}
