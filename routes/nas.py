import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from core.database import execute, query
from core.security import require_config

router = APIRouter(prefix="/api/nas", tags=["Clientes NAS"], dependencies=[Depends(require_config)])
TACACS_DEVICE_GROUPS_FILE = Path("/usr/local/etc/tac_plus-ng/axio_device_groups.json")


def ensure_schema():
    execute(
        """
        CREATE TABLE IF NOT EXISTS axio_nas_groups (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(120) NOT NULL UNIQUE,
            parent_id INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_axio_nas_groups_parent
                FOREIGN KEY (parent_id) REFERENCES axio_nas_groups(id)
                ON DELETE SET NULL
        )
        """
    )
    execute(
        """
        CREATE TABLE IF NOT EXISTS axio_site_nodes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(160) NOT NULL,
            code VARCHAR(80) NULL,
            node_type VARCHAR(32) NOT NULL DEFAULT 'site',
            parent_id INT NULL,
            description VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_axio_site_parent_name (parent_id, name),
            CONSTRAINT fk_axio_site_nodes_parent
                FOREIGN KEY (parent_id) REFERENCES axio_site_nodes(id)
                ON DELETE SET NULL
        )
        """
    )

    alter_statements = [
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS server VARCHAR(64) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS community VARCHAR(128) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS group_id INT NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS device_series VARCHAR(80) NULL DEFAULT 'other'",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS location VARCHAR(190) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS radius_enabled TINYINT(1) NOT NULL DEFAULT 1",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS tacacs_enabled TINYINT(1) NOT NULL DEFAULT 0",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS tacacs_secret VARCHAR(128) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS vendor VARCHAR(120) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS model VARCHAR(120) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS serial_number VARCHAR(120) NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS site_node_id INT NULL",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS criticality VARCHAR(24) NOT NULL DEFAULT 'medium'",
        "ALTER TABLE nas ADD COLUMN IF NOT EXISTS last_inventory_sync TIMESTAMP NULL",
    ]
    for statement in alter_statements:
        execute(statement)
    try:
        execute(
            """
            ALTER TABLE nas
            ADD CONSTRAINT fk_nas_site_node
            FOREIGN KEY (site_node_id) REFERENCES axio_site_nodes(id)
            ON DELETE SET NULL
            """
        )
    except Exception:
        pass


class NASCreate(BaseModel):
    nasname: str
    shortname: str = ""
    type: str = "other"
    ports: Optional[int] = 1812
    secret: str
    server: Optional[str] = None
    community: Optional[str] = None
    description: Optional[str] = "RADIUS Client"
    group_id: Optional[int] = None
    device_series: Optional[str] = "other"
    location: Optional[str] = None
    radius_enabled: bool = True
    tacacs_enabled: bool = False
    tacacs_secret: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site_node_id: Optional[int] = None
    criticality: str = "medium"


class NASUpdate(BaseModel):
    nasname: Optional[str] = None
    shortname: Optional[str] = None
    type: Optional[str] = None
    ports: Optional[int] = None
    secret: Optional[str] = None
    server: Optional[str] = None
    community: Optional[str] = None
    description: Optional[str] = None
    group_id: Optional[int] = None
    device_series: Optional[str] = None
    location: Optional[str] = None
    radius_enabled: Optional[bool] = None
    tacacs_enabled: Optional[bool] = None
    tacacs_secret: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    site_node_id: Optional[int] = None
    criticality: Optional[str] = None


class NASGroupCreate(BaseModel):
    name: str
    parent_id: Optional[int] = None


class NASGroupUpdate(BaseModel):
    name: str


class SiteNodeCreate(BaseModel):
    name: str
    code: Optional[str] = None
    node_type: str = "site"
    parent_id: Optional[int] = None
    description: Optional[str] = None


class SiteNodeUpdate(BaseModel):
    name: Optional[str] = None
    code: Optional[str] = None
    node_type: Optional[str] = None
    parent_id: Optional[int] = None
    description: Optional[str] = None


def validate_group(group_id: Optional[int]) -> Optional[int]:
    if not group_id:
        return None
    row = query("SELECT id FROM axio_nas_groups WHERE id = %s", (group_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Grupo NAS no encontrado")
    return group_id


def validate_site_node(site_node_id: Optional[int]) -> Optional[int]:
    if not site_node_id:
        return None
    row = query("SELECT id FROM axio_site_nodes WHERE id = %s", (site_node_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Nodo de topologia no encontrado")
    return site_node_id


def normalize_criticality(value: Optional[str]) -> str:
    normalized = str(value or "medium").strip().lower()
    if normalized not in {"low", "medium", "high", "critical"}:
        raise HTTPException(status_code=400, detail="criticality debe ser low, medium, high o critical")
    return normalized


def read_tacacs_device_groups() -> list[dict]:
    if not TACACS_DEVICE_GROUPS_FILE.exists():
        return []
    try:
        rows = json.loads(TACACS_DEVICE_GROUPS_FILE.read_text(encoding="utf-8"))
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def _build_topology_tree(rows: list[dict]) -> list[dict]:
    by_parent: dict[Optional[int], list[dict]] = {}
    for row in rows:
        by_parent.setdefault(row.get("parent_id"), []).append(row)
    for items in by_parent.values():
        items.sort(key=lambda item: str(item.get("name") or "").lower())

    def build(parent_id: Optional[int]) -> list[dict]:
        result = []
        for node in by_parent.get(parent_id, []):
            result.append(
                {
                    "id": node["id"],
                    "name": node["name"],
                    "code": node.get("code"),
                    "node_type": node.get("node_type") or "site",
                    "description": node.get("description"),
                    "children": build(node["id"]),
                }
            )
        return result

    return build(None)


def serialize_nas(row: dict) -> dict:
    return {
        "id": row["id"],
        "nasname": row["nasname"],
        "shortname": row.get("shortname"),
        "type": row.get("type") or "other",
        "ports": row.get("ports"),
        "secret": row.get("secret"),
        "server": row.get("server"),
        "community": row.get("community"),
        "description": row.get("description"),
        "group_id": row.get("group_id"),
        "group_name": row.get("group_name"),
        "device_series": row.get("device_series") or "other",
        "location": row.get("location"),
        "radius_enabled": bool(row.get("radius_enabled", 1)),
        "tacacs_enabled": bool(row.get("tacacs_enabled", 0)),
        "tacacs_secret": row.get("tacacs_secret"),
        "vendor": row.get("vendor"),
        "model": row.get("model"),
        "serial_number": row.get("serial_number"),
        "site_node_id": row.get("site_node_id"),
        "site_node_name": row.get("site_node_name"),
        "criticality": row.get("criticality") or "medium",
    }


@router.get("", summary="Listar clientes NAS")
@router.get("/", include_in_schema=False, summary="Listar clientes NAS")
def list_nas(group_id: Optional[int] = Query(None)):
    ensure_schema()
    sql = """
        SELECT
            n.id,
            n.nasname,
            n.shortname,
            n.type,
            n.ports,
            n.secret,
            n.server,
            n.community,
            n.description,
            n.group_id,
            g.name AS group_name,
            n.device_series,
            n.location,
            n.radius_enabled,
            n.tacacs_enabled,
            n.tacacs_secret,
            n.vendor,
            n.model,
            n.serial_number,
            n.site_node_id,
            s.name AS site_node_name,
            n.criticality
        FROM nas n
        LEFT JOIN axio_nas_groups g ON g.id = n.group_id
        LEFT JOIN axio_site_nodes s ON s.id = n.site_node_id
    """
    params = ()
    if group_id:
        sql += " WHERE n.group_id = %s"
        params = (group_id,)
    sql += " ORDER BY COALESCE(n.shortname, n.nasname)"
    return [serialize_nas(row) for row in query(sql, params)]


@router.get("/groups", summary="Listar grupos NAS")
@router.get("/groups/", include_in_schema=False, summary="Listar grupos NAS")
def list_nas_groups():
    ensure_schema()
    rows = query(
        """
        SELECT
            g.id,
            g.name,
            g.parent_id,
            COUNT(n.id) AS nas_count
        FROM axio_nas_groups g
        LEFT JOIN nas n ON n.group_id = g.id
        GROUP BY g.id, g.name, g.parent_id
        ORDER BY g.name
        """
    )
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "parent_id": row["parent_id"],
            "nas_count": int(row["nas_count"] or 0),
        }
        for row in rows
    ]


@router.get("/topology", summary="Arbol de sedes/zonas de dispositivos")
@router.get("/topology/", include_in_schema=False, summary="Arbol de sedes/zonas de dispositivos")
def list_topology():
    ensure_schema()
    rows = query(
        """
        SELECT id, name, code, node_type, parent_id, description
        FROM axio_site_nodes
        ORDER BY parent_id, name
        """
    )
    return {"items": rows, "tree": _build_topology_tree(rows), "total": len(rows)}


@router.post("/topology", status_code=201, summary="Crear nodo de topologia")
@router.post("/topology/", include_in_schema=False, status_code=201, summary="Crear nodo de topologia")
def create_topology_node(data: SiteNodeCreate):
    ensure_schema()
    name = (data.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre del nodo es obligatorio")
    parent_id = validate_site_node(data.parent_id)
    node_type = (data.node_type or "site").strip().lower()
    if node_type not in {"site", "zone", "region", "building", "floor", "room"}:
        raise HTTPException(status_code=400, detail="node_type no valido")
    existing = query(
        "SELECT id FROM axio_site_nodes WHERE LOWER(name) = LOWER(%s) AND ((parent_id = %s) OR (parent_id IS NULL AND %s IS NULL))",
        (name, parent_id, parent_id),
        fetchone=True,
    )
    if existing:
        raise HTTPException(status_code=409, detail="Ya existe un nodo con ese nombre en el mismo parent")
    node_id = execute(
        "INSERT INTO axio_site_nodes (name, code, node_type, parent_id, description) VALUES (%s, %s, %s, %s, %s)",
        (name, (data.code or "").strip() or None, node_type, parent_id, (data.description or "").strip() or None),
    )
    return {"ok": True, "id": node_id}


@router.put("/topology/{node_id}", summary="Actualizar nodo de topologia")
@router.put("/topology/{node_id}/", include_in_schema=False, summary="Actualizar nodo de topologia")
def update_topology_node(node_id: int, data: SiteNodeUpdate):
    ensure_schema()
    current = query("SELECT id FROM axio_site_nodes WHERE id = %s", (node_id,), fetchone=True)
    if not current:
        raise HTTPException(status_code=404, detail="Nodo de topologia no encontrado")
    fields = {k: v for k, v in data.model_dump().items() if v is not None}
    if "parent_id" in fields:
        new_parent = validate_site_node(fields["parent_id"])
        if new_parent == node_id:
            raise HTTPException(status_code=400, detail="Un nodo no puede ser padre de si mismo")
        fields["parent_id"] = new_parent
    if "node_type" in fields:
        node_type = str(fields["node_type"]).strip().lower()
        if node_type not in {"site", "zone", "region", "building", "floor", "room"}:
            raise HTTPException(status_code=400, detail="node_type no valido")
        fields["node_type"] = node_type
    if "name" in fields:
        name = str(fields["name"]).strip()
        if not name:
            raise HTTPException(status_code=400, detail="El nombre del nodo es obligatorio")
        fields["name"] = name
    if "code" in fields:
        fields["code"] = str(fields["code"]).strip() or None
    if "description" in fields:
        fields["description"] = str(fields["description"]).strip() or None
    if not fields:
        return {"ok": True, "id": node_id, "message": "Nada que actualizar"}
    set_clause = ", ".join(f"{key} = %s" for key in fields.keys())
    execute(f"UPDATE axio_site_nodes SET {set_clause} WHERE id = %s", tuple(fields.values()) + (node_id,))
    return {"ok": True, "id": node_id}


@router.delete("/topology/{node_id}", summary="Eliminar nodo de topologia")
@router.delete("/topology/{node_id}/", include_in_schema=False, summary="Eliminar nodo de topologia")
def delete_topology_node(node_id: int):
    ensure_schema()
    row = query("SELECT id FROM axio_site_nodes WHERE id = %s", (node_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Nodo de topologia no encontrado")
    execute("UPDATE axio_site_nodes SET parent_id = NULL WHERE parent_id = %s", (node_id,))
    execute("UPDATE nas SET site_node_id = NULL WHERE site_node_id = %s", (node_id,))
    execute("DELETE FROM axio_site_nodes WHERE id = %s", (node_id,))
    return {"ok": True, "deleted": node_id}


@router.post("/groups", status_code=201, summary="Crear grupo NAS")
@router.post("/groups/", include_in_schema=False, status_code=201, summary="Crear grupo NAS")
def create_nas_group(data: NASGroupCreate):
    ensure_schema()
    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre del grupo es obligatorio")

    parent_id = validate_group(data.parent_id)
    existing = query("SELECT id FROM axio_nas_groups WHERE LOWER(name) = LOWER(%s)", (name,), fetchone=True)
    if existing:
        raise HTTPException(status_code=409, detail="Ya existe un grupo con ese nombre")

    group_id = execute("INSERT INTO axio_nas_groups (name, parent_id) VALUES (%s, %s)", (name, parent_id))
    return {"ok": True, "id": group_id, "name": name}


@router.put("/groups/{group_id}", summary="Actualizar grupo NAS")
@router.put("/groups/{group_id}/", include_in_schema=False, summary="Actualizar grupo NAS")
def update_nas_group(group_id: int, data: NASGroupUpdate):
    ensure_schema()
    row = query("SELECT id FROM axio_nas_groups WHERE id = %s", (group_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Grupo NAS no encontrado")

    name = data.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="El nombre del grupo es obligatorio")

    existing = query("SELECT id FROM axio_nas_groups WHERE LOWER(name) = LOWER(%s) AND id <> %s", (name, group_id), fetchone=True)
    if existing:
        raise HTTPException(status_code=409, detail="Ya existe otro grupo con ese nombre")

    execute("UPDATE axio_nas_groups SET name = %s WHERE id = %s", (name, group_id))
    return {"ok": True, "id": group_id, "name": name}


@router.delete("/groups/{group_id}", summary="Eliminar grupo NAS")
@router.delete("/groups/{group_id}/", include_in_schema=False, summary="Eliminar grupo NAS")
def delete_nas_group(group_id: int):
    ensure_schema()
    row = query("SELECT id FROM axio_nas_groups WHERE id = %s", (group_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="Grupo NAS no encontrado")

    execute("UPDATE axio_nas_groups SET parent_id = NULL WHERE parent_id = %s", (group_id,))
    execute("UPDATE nas SET group_id = NULL WHERE group_id = %s", (group_id,))
    execute("DELETE FROM axio_nas_groups WHERE id = %s", (group_id,))
    return {"ok": True, "deleted": group_id}


@router.get("/{nas_id}", summary="Detalle de un NAS")
@router.get("/{nas_id}/", include_in_schema=False, summary="Detalle de un NAS")
def get_nas(nas_id: int):
    ensure_schema()
    row = query(
        """
        SELECT
            n.*,
            g.name AS group_name,
            s.name AS site_node_name
        FROM nas n
        LEFT JOIN axio_nas_groups g ON g.id = n.group_id
        LEFT JOIN axio_site_nodes s ON s.id = n.site_node_id
        WHERE n.id = %s
        """,
        (nas_id,),
        fetchone=True,
    )
    if not row:
        raise HTTPException(status_code=404, detail="NAS no encontrado")
    return serialize_nas(row)


@router.post("", status_code=201, summary="Agregar cliente NAS")
@router.post("/", include_in_schema=False, status_code=201, summary="Agregar cliente NAS")
def create_nas(data: NASCreate):
    ensure_schema()
    existing = query("SELECT id FROM nas WHERE nasname = %s", (data.nasname.strip(),), fetchone=True)
    if existing:
        raise HTTPException(status_code=409, detail="Ya existe un NAS con esa IP/hostname")

    group_id = validate_group(data.group_id)
    site_node_id = validate_site_node(data.site_node_id)
    criticality = normalize_criticality(data.criticality)
    nas_id = execute(
        """
        INSERT INTO nas (
            nasname, shortname, type, ports, secret, server, community, description,
            group_id, device_series, location, radius_enabled, tacacs_enabled, tacacs_secret,
            vendor, model, serial_number, site_node_id, criticality
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            data.nasname.strip(),
            data.shortname.strip(),
            data.type,
            data.ports,
            data.secret,
            data.server,
            data.community,
            data.description,
            group_id,
            data.device_series or "other",
            data.location,
            1 if data.radius_enabled else 0,
            1 if data.tacacs_enabled else 0,
            data.tacacs_secret,
            (data.vendor or "").strip() or None,
            (data.model or "").strip() or None,
            (data.serial_number or "").strip() or None,
            site_node_id,
            criticality,
        ),
    )
    return {"ok": True, "id": nas_id, "nasname": data.nasname.strip()}


@router.put("/{nas_id}", summary="Actualizar cliente NAS")
@router.put("/{nas_id}/", include_in_schema=False, summary="Actualizar cliente NAS")
def update_nas(nas_id: int, data: NASUpdate):
    ensure_schema()
    row = query("SELECT id FROM nas WHERE id = %s", (nas_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="NAS no encontrado")

    fields = {k: v for k, v in data.model_dump().items() if v is not None}
    if "group_id" in fields:
        fields["group_id"] = validate_group(fields["group_id"])
    if "site_node_id" in fields:
        fields["site_node_id"] = validate_site_node(fields["site_node_id"])
    if "radius_enabled" in fields:
        fields["radius_enabled"] = 1 if fields["radius_enabled"] else 0
    if "tacacs_enabled" in fields:
        fields["tacacs_enabled"] = 1 if fields["tacacs_enabled"] else 0
    if "nasname" in fields:
        fields["nasname"] = fields["nasname"].strip()
        existing = query("SELECT id FROM nas WHERE nasname = %s AND id <> %s", (fields["nasname"], nas_id), fetchone=True)
        if existing:
            raise HTTPException(status_code=409, detail="Ya existe otro NAS con esa IP/hostname")
    if "shortname" in fields and fields["shortname"] is not None:
        fields["shortname"] = fields["shortname"].strip()
    if "criticality" in fields:
        fields["criticality"] = normalize_criticality(fields["criticality"])
    for key in ("vendor", "model", "serial_number", "location", "device_series", "server", "community", "description", "tacacs_secret"):
        if key in fields and fields[key] is not None:
            fields[key] = str(fields[key]).strip() or None

    if not fields:
        return {"ok": True, "message": "Nada que actualizar"}

    set_clause = ", ".join(f"{key} = %s" for key in fields.keys())
    values = list(fields.values()) + [nas_id]
    execute(f"UPDATE nas SET {set_clause} WHERE id = %s", tuple(values))
    return {"ok": True, "id": nas_id}


@router.delete("/{nas_id}", summary="Eliminar cliente NAS")
@router.delete("/{nas_id}/", include_in_schema=False, summary="Eliminar cliente NAS")
def delete_nas(nas_id: int):
    ensure_schema()
    row = query("SELECT id FROM nas WHERE id = %s", (nas_id,), fetchone=True)
    if not row:
        raise HTTPException(status_code=404, detail="NAS no encontrado")
    execute("DELETE FROM nas WHERE id = %s", (nas_id,))
    return {"ok": True, "deleted": nas_id}


@router.get("/live/status", summary="Estado en vivo del inventario NAS")
@router.get("/live/status/", include_in_schema=False, summary="Estado en vivo del inventario NAS")
def nas_live_status():
    ensure_schema()
    rows = query(
        """
        SELECT
            n.id,
            n.nasname,
            COALESCE(n.shortname, n.nasname) AS shortname,
            n.group_id,
            g.name AS group_name,
            n.site_node_id,
            s.name AS site_node_name,
            n.criticality,
            n.vendor,
            n.model,
            n.serial_number
        FROM nas n
        LEFT JOIN axio_nas_groups g ON g.id = n.group_id
        LEFT JOIN axio_site_nodes s ON s.id = n.site_node_id
        ORDER BY COALESCE(n.shortname, n.nasname)
        """
    )
    active_rows = query(
        """
        SELECT nasipaddress, COUNT(*) AS active_sessions
        FROM radacct
        WHERE acctstoptime IS NULL
        GROUP BY nasipaddress
        """
    )
    last_auth_rows = query(
        """
        SELECT nasipaddress, MAX(authdate) AS last_auth_at
        FROM radpostauth
        GROUP BY nasipaddress
        """
    )
    tacacs_groups = read_tacacs_device_groups()
    active_by_ip = {str(row.get("nasipaddress") or "").strip().lower(): int(row.get("active_sessions") or 0) for row in active_rows}
    last_auth_by_ip = {str(row.get("nasipaddress") or "").strip().lower(): row.get("last_auth_at") for row in last_auth_rows}

    def matched_device_groups(nasname: str, shortname: str) -> list[str]:
        targets = {str(nasname or "").strip().lower(), str(shortname or "").strip().lower()}
        names = []
        for group in tacacs_groups:
            group_name = str(group.get("name") or "").strip()
            devices = [str(d or "").strip().lower() for d in (group.get("devices") or []) if str(d or "").strip()]
            if any(target in devices for target in targets):
                names.append(group_name)
        return names

    items = []
    for row in rows:
        ip_key = str(row.get("nasname") or "").strip().lower()
        active_sessions = int(active_by_ip.get(ip_key, 0))
        last_auth_at = last_auth_by_ip.get(ip_key)
        reachable = active_sessions > 0 or bool(last_auth_at)
        criticality = str(row.get("criticality") or "medium").lower()
        crit_penalty = {"low": 0, "medium": 5, "high": 10, "critical": 15}.get(criticality, 5)
        score = 40
        if reachable:
            score += 35
        if active_sessions > 0:
            score += 20
        if last_auth_at:
            score += 15
        health_score = max(0, min(100, score - crit_penalty))
        items.append(
            {
                "id": row["id"],
                "nasname": row["nasname"],
                "shortname": row.get("shortname"),
                "group_id": row.get("group_id"),
                "group_name": row.get("group_name"),
                "site_node_id": row.get("site_node_id"),
                "site_node_name": row.get("site_node_name"),
                "criticality": criticality,
                "vendor": row.get("vendor"),
                "model": row.get("model"),
                "serial_number": row.get("serial_number"),
                "reachability": "up" if reachable else "down",
                "active_sessions": active_sessions,
                "last_auth_at": last_auth_at,
                "health_score": health_score,
                "tacacs_device_groups": matched_device_groups(row.get("nasname"), row.get("shortname")),
            }
        )

    up_count = sum(1 for item in items if item["reachability"] == "up")
    return {
        "total": len(items),
        "up": up_count,
        "down": len(items) - up_count,
        "avg_health_score": int(sum(item["health_score"] for item in items) / len(items)) if items else 0,
        "items": items,
    }
