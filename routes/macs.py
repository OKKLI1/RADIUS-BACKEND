"""
routes/macs.py
Gestión de MACs para autenticación RADIUS MAB.

Estados de una MAC:
  pending  → registrada pero sin aprobar (Access-Reject)
  active   → aprobada y con carpeta empresa → puede autenticar (Access-Accept)
  disabled → desactivada manualmente (Access-Reject)

Para que una MAC pueda autenticarse necesita:
  1. status = 'active'
  2. Estar asignada a una carpeta is_company=1 o subcarpeta de ella
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from core.security import require_helpdesk, require_admin
from core.database import query, execute

router = APIRouter(prefix="/api/macs", tags=["MACs"])

STATUS_LABELS = {
    'pending':  '⏳ Pendiente',
    'active':   '✅ Activa',
    'disabled': '🚫 Desactivada',
}

def mac_formats(mac_normalized: str) -> dict:
    clean = mac_normalized.replace(":", "")
    return {
        "upper_colon": mac_normalized.upper(),
        "lower_colon": mac_normalized.lower(),
        "lower_plain":  clean.lower(),
    }


class MacCreate(BaseModel):
    mac: str
    username: str
    description: Optional[str] = ""


class MacStatusUpdate(BaseModel):
    status: str  # active | disabled | pending
    note: Optional[str] = ""


@router.get("", summary="Listar MACs registradas")
@router.get("/", include_in_schema=False)
def list_macs(payload: dict = Depends(require_helpdesk)):
    rows = query(
        """SELECT
               m.id,
               m.mac,
               m.username,
               m.description,
               m.status,
               m.registered_by,
               m.approved_by,
               m.approved_at,
               m.status_note,
               m.created_at
           FROM axio_mac_registry m
           ORDER BY m.created_at DESC"""
    )
    return rows


@router.post("", summary="Registrar nueva MAC")
@router.post("/", include_in_schema=False)
def create_mac(data: MacCreate, request: Request,
               payload: dict = Depends(require_helpdesk)):
    mac = data.mac.upper()
    existing = query("SELECT id FROM axio_mac_registry WHERE mac = %s", (mac,), fetchone=True)
    if existing:
        raise HTTPException(400, f"La MAC {mac} ya está registrada.")

    formats = mac_formats(mac)
    ids = []
    for fmt_value in formats.values():
        rid = execute(
            "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, 'Cleartext-Password', ':=', %s)",
            (fmt_value, fmt_value)
        )
        ids.append(rid)

    primary_id = ids[0]
    registry_id = execute(
        """INSERT INTO axio_mac_registry
           (radcheck_id, mac, username, description, registered_by, status, created_at)
           VALUES (%s, %s, %s, %s, %s, 'pending', %s)""",
        (primary_id, mac, data.username,
         data.description or "", payload.get("sub"), datetime.utcnow())
    )
    return {"ok": True, "id": registry_id, "radcheck_id": primary_id, "mac": mac,
            "username": data.username, "status": "pending"}


@router.put("/{mac_id}/status", summary="Aprobar, desactivar o poner en pendiente una MAC")
def update_mac_status(mac_id: int, data: MacStatusUpdate,
                      payload: dict = Depends(require_admin)):
    if data.status not in ("active", "disabled", "pending"):
        raise HTTPException(400, "Status inválido. Usa: active, disabled, pending")

    reg = query("SELECT id, mac, status, radcheck_id FROM axio_mac_registry WHERE id = %s",
                (mac_id,), fetchone=True)
    if not reg:
        raise HTTPException(404, "MAC no encontrada.")

    # Si se va a activar, verificar que tenga carpeta empresa asignada
    if data.status == "active":
        has_company_folder = query(
            """SELECT 1 FROM axio_mac_folders mf
               JOIN axio_folders f ON f.id = mf.folder_id
               WHERE mf.mac_id = %s
               AND (
                 f.is_company = 1
                 OR f.parent_id IN (SELECT id FROM axio_folders WHERE is_company = 1)
                 OR f.parent_id IN (
                   SELECT f2.id FROM axio_folders f2
                   JOIN axio_folders f3 ON f2.parent_id = f3.id
                   WHERE f3.is_company = 1
                 )
                 OR f.parent_id IN (
                   SELECT f2.id FROM axio_folders f2
                   JOIN axio_folders f3 ON f2.parent_id = f3.id
                   JOIN axio_folders f4 ON f3.parent_id = f4.id
                   WHERE f4.is_company = 1
                 )
               )
               LIMIT 1""",
            (reg["radcheck_id"],),
            fetchone=True
        )
        if not has_company_folder:
            raise HTTPException(
                400,
                "No se puede activar: la MAC no está asignada a ninguna carpeta empresa "
                "ni subcarpeta. Asígnala primero a ENGIE o una de sus subcarpetas."
            )

    approved_by = payload.get("sub") if data.status == "active" else None
    approved_at = datetime.utcnow() if data.status == "active" else None

    execute(
        """UPDATE axio_mac_registry
           SET status = %s, approved_by = %s, approved_at = %s, status_note = %s
           WHERE id = %s""",
        (data.status, approved_by, approved_at, data.note or "", mac_id)
    )
    return {"ok": True, "mac_id": mac_id, "status": data.status}


@router.delete("/{mac_id}", summary="Eliminar MAC (todos los formatos)")
def delete_mac(mac_id: int, payload: dict = Depends(require_admin)):
    reg = query("SELECT mac, radcheck_id FROM axio_mac_registry WHERE id = %s",
                (mac_id,), fetchone=True)
    if not reg:
        raise HTTPException(404, "MAC no encontrada.")

    formats = mac_formats(reg["mac"])
    for fmt_value in formats.values():
        execute(
            "DELETE FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
            (fmt_value,)
        )
    execute("DELETE FROM axio_mac_registry WHERE id = %s", (mac_id,))
    return {"ok": True}
