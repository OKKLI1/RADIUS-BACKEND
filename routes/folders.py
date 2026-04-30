"""
routes/folders.py
CRUD de carpetas y asignación de MACs a carpetas.
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from core.security import require_helpdesk, require_config, require_admin
from core.database import query, execute

router = APIRouter(prefix="/api/folders", tags=["Carpetas"])


class FolderCreate(BaseModel):
    name: str
    parent_id: Optional[int] = None


class FolderRename(BaseModel):
    name: str


# ── CRUD Carpetas ──────────────────────────────────────────────────────────────

@router.get("", summary="Listar todas las carpetas (árbol completo)")
@router.get("/", include_in_schema=False)
def list_folders(payload: dict = Depends(require_helpdesk)):
    """
    Devuelve todas las carpetas con conteo de MACs asignadas.
    El frontend construye el árbol con parent_id.
    """
    rows = query(
        """SELECT
               f.id,
               f.name,
               f.parent_id,
               f.is_company,
               f.created_by,
               f.created_at,
               COUNT(mf.mac_id) AS mac_count
           FROM axio_folders f
           LEFT JOIN axio_mac_folders mf ON mf.folder_id = f.id
           GROUP BY f.id
           ORDER BY f.parent_id IS NULL DESC, f.name ASC"""
    )
    return rows


@router.post("", summary="Crear carpeta")
@router.post("/", include_in_schema=False)
def create_folder(data: FolderCreate, payload: dict = Depends(require_helpdesk)):
    if not data.name.strip():
        raise HTTPException(400, "El nombre no puede estar vacío.")
    if data.parent_id:
        parent = query("SELECT id FROM axio_folders WHERE id = %s",
                       (data.parent_id,), fetchone=True)
        if not parent:
            raise HTTPException(404, "Carpeta padre no encontrada.")
    folder_id = execute(
        "INSERT INTO axio_folders (name, parent_id, created_by, created_at) VALUES (%s, %s, %s, %s)",
        (data.name.strip(), data.parent_id, payload.get("sub"), datetime.utcnow())
    )
    return {"ok": True, "id": folder_id, "name": data.name.strip(), "parent_id": data.parent_id}


@router.put("/{folder_id}", summary="Renombrar carpeta")
def rename_folder(folder_id: int, data: FolderRename,
                  payload: dict = Depends(require_helpdesk)):
    if not data.name.strip():
        raise HTTPException(400, "El nombre no puede estar vacío.")
    existing = query("SELECT id FROM axio_folders WHERE id = %s", (folder_id,), fetchone=True)
    if not existing:
        raise HTTPException(404, "Carpeta no encontrada.")
    execute("UPDATE axio_folders SET name = %s WHERE id = %s",
            (data.name.strip(), folder_id))
    return {"ok": True}


@router.delete("/{folder_id}", summary="Eliminar carpeta (y subcarpetas en cascada)")
def delete_folder(folder_id: int, payload: dict = Depends(require_helpdesk)):
    existing = query("SELECT id FROM axio_folders WHERE id = %s", (folder_id,), fetchone=True)
    if not existing:
        raise HTTPException(404, "Carpeta no encontrada.")
    execute("DELETE FROM axio_folders WHERE id = %s", (folder_id,))
    return {"ok": True}


# ── MACs en carpeta ────────────────────────────────────────────────────────────

@router.get("/{folder_id}/macs", summary="MACs asignadas a una carpeta")
def get_folder_macs(folder_id: int, payload: dict = Depends(require_helpdesk)):
    rows = query(
        """SELECT
               reg.id,
               reg.mac,
               reg.username,
               reg.description,
               reg.status,
               reg.approved_by,
               reg.approved_at,
               reg.status_note,
               reg.registered_by,
               reg.created_at,
               mf.assigned_at
           FROM axio_mac_folders mf
           JOIN axio_mac_registry reg ON reg.radcheck_id = mf.mac_id
           WHERE mf.folder_id = %s
           ORDER BY mf.assigned_at DESC""",
        (folder_id,)
    )
    return rows


@router.post("/{folder_id}/macs/{registry_id}", summary="Asignar MAC a carpeta")
def assign_mac_to_folder(folder_id: int, registry_id: int,
                         payload: dict = Depends(require_helpdesk)):
    folder = query("SELECT id FROM axio_folders WHERE id = %s", (folder_id,), fetchone=True)
    if not folder:
        raise HTTPException(404, "Carpeta no encontrada.")
    # registry_id es el id de axio_mac_registry
    reg = query("SELECT radcheck_id FROM axio_mac_registry WHERE id = %s", (registry_id,), fetchone=True)
    if not reg:
        raise HTTPException(404, "MAC no encontrada.")
    radcheck_id = reg["radcheck_id"]
    existing = query("SELECT mac_id FROM axio_mac_folders WHERE mac_id = %s AND folder_id = %s",
                     (radcheck_id, folder_id), fetchone=True)
    if existing:
        raise HTTPException(400, "La MAC ya está asignada a esta carpeta.")
    execute(
        "INSERT INTO axio_mac_folders (mac_id, folder_id, assigned_by, assigned_at) VALUES (%s, %s, %s, %s)",
        (radcheck_id, folder_id, payload.get("sub"), datetime.utcnow())
    )
    return {"ok": True}


@router.delete("/{folder_id}/macs/{registry_id}", summary="Quitar MAC de carpeta")
def remove_mac_from_folder(folder_id: int, registry_id: int,
                           payload: dict = Depends(require_helpdesk)):
    reg = query("SELECT radcheck_id FROM axio_mac_registry WHERE id = %s", (registry_id,), fetchone=True)
    if not reg:
        raise HTTPException(404, "MAC no encontrada.")
    execute("DELETE FROM axio_mac_folders WHERE mac_id = %s AND folder_id = %s",
            (reg["radcheck_id"], folder_id))
    return {"ok": True}


# ── Carpetas de una MAC ────────────────────────────────────────────────────────

@router.get("/by-mac/{registry_id}", summary="Carpetas a las que pertenece una MAC")
def get_mac_folders(registry_id: int, payload: dict = Depends(require_helpdesk)):
    # Obtener radcheck_id desde axio_mac_registry
    reg = query("SELECT radcheck_id FROM axio_mac_registry WHERE id = %s", (registry_id,), fetchone=True)
    if not reg:
        return []
    rows = query(
        """SELECT f.id, f.name, f.parent_id
           FROM axio_mac_folders mf
           JOIN axio_folders f ON f.id = mf.folder_id
           WHERE mf.mac_id = %s
           ORDER BY f.name""",
        (reg["radcheck_id"],)
    )
    return rows


# ── Marcar carpeta como empresa ────────────────────────────────────────────────

@router.put("/{folder_id}/company", summary="Marcar/desmarcar carpeta como empresa habilitadora")
def set_company_folder(folder_id: int, payload: dict = Depends(require_admin)):
    folder = query("SELECT id, name, is_company FROM axio_folders WHERE id = %s",
                   (folder_id,), fetchone=True)
    if not folder:
        raise HTTPException(404, "Carpeta no encontrada.")
    new_value = 0 if folder["is_company"] else 1
    execute("UPDATE axio_folders SET is_company = %s WHERE id = %s", (new_value, folder_id))
    return {"ok": True, "folder_id": folder_id, "is_company": bool(new_value)}
