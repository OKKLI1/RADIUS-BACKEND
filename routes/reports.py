from fastapi import APIRouter, Depends, Query
from typing import Optional
from core.database import query
from core.security import require_config

router = APIRouter(prefix="/api/reports", tags=["Reportes"], dependencies=[Depends(require_config)])


@router.get("/dashboard", summary="Estadísticas generales para el dashboard")
def dashboard_stats():
    """Retorna todos los contadores necesarios para el panel principal."""

    total_users = query(
        "SELECT COUNT(DISTINCT username) AS total FROM radcheck WHERE attribute = 'Cleartext-Password'",
        fetchone=True
    )
    active_sessions = query(
        "SELECT COUNT(*) AS total FROM radacct WHERE acctstoptime IS NULL",
        fetchone=True
    )
    nas_count = query("SELECT COUNT(*) AS total FROM nas", fetchone=True)
    auth_ok = query(
        "SELECT COUNT(*) AS total FROM radpostauth WHERE reply='Access-Accept' AND authdate >= NOW() - INTERVAL 24 HOUR",
        fetchone=True
    )
    auth_fail = query(
        "SELECT COUNT(*) AS total FROM radpostauth WHERE reply='Access-Reject' AND authdate >= NOW() - INTERVAL 24 HOUR",
        fetchone=True
    )
    traffic_today = query("""
        SELECT
            COALESCE(SUM(acctinputoctets), 0)  AS upload_bytes,
            COALESCE(SUM(acctoutputoctets), 0) AS download_bytes
        FROM radacct
        WHERE DATE(acctstarttime) = CURDATE()
    """, fetchone=True)

    return {
        "total_users":       total_users["total"],
        "active_sessions":   active_sessions["total"],
        "nas_count":         nas_count["total"],
        "auth_ok_24h":       auth_ok["total"],
        "auth_fail_24h":     auth_fail["total"],
        "traffic_today":     traffic_today,
    }


@router.get("/traffic/daily", summary="Tráfico diario (últimos N días)")
def daily_traffic(days: int = Query(30, ge=1, le=365)):
    """Tráfico agregado por día para gráficos de línea/barra."""
    rows = query("""
        SELECT
            DATE(acctstarttime)               AS date,
            COUNT(*)                          AS sessions,
            SUM(acctinputoctets)              AS upload_bytes,
            SUM(acctoutputoctets)             AS download_bytes,
            SUM(acctinputoctets + acctoutputoctets) AS total_bytes
        FROM radacct
        WHERE acctstarttime >= NOW() - INTERVAL %s DAY
        GROUP BY DATE(acctstarttime)
        ORDER BY date ASC
    """, (days,))
    return rows


@router.get("/top-users", summary="Top usuarios por consumo de datos")
def top_users(
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(30, ge=1, le=365),
):
    return query("""
        SELECT
            username,
            COUNT(*)                                        AS sessions,
            SUM(acctsessiontime)                           AS total_seconds,
            SUM(acctinputoctets)                           AS upload_bytes,
            SUM(acctoutputoctets)                          AS download_bytes,
            SUM(acctinputoctets + acctoutputoctets)        AS total_bytes
        FROM radacct
        WHERE acctstarttime >= NOW() - INTERVAL %s DAY
        GROUP BY username
        ORDER BY total_bytes DESC
        LIMIT %s
    """, (days, limit))


@router.get("/by-nas", summary="Tráfico agrupado por NAS")
def traffic_by_nas(days: int = Query(30, ge=1, le=365)):
    return query("""
        SELECT
            r.nasipaddress,
            n.shortname,
            COUNT(*)                                        AS sessions,
            SUM(r.acctinputoctets + r.acctoutputoctets)    AS total_bytes
        FROM radacct r
        LEFT JOIN nas n ON r.nasipaddress = n.nasname
        WHERE r.acctstarttime >= NOW() - INTERVAL %s DAY
        GROUP BY r.nasipaddress, n.shortname
        ORDER BY total_bytes DESC
    """, (days,))

@router.get("/batch/summary", summary="Resumen para reportes de usuarios batch")
@router.get("/batch/summary/", include_in_schema=False)
def batch_summary(
    batch_name: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=200),
):
    prefix = (batch_name or "").strip()
    like_value = f"{prefix}%" if prefix else "%"

    totals = query(
        """
        SELECT
            COUNT(DISTINCT rc.username) AS total_users,
            SUM(rc.username LIKE 'VCH-%') AS total_vouchers
        FROM radcheck rc
        WHERE rc.attribute = 'Cleartext-Password'
          AND rc.username LIKE %s
        """,
        (like_value,),
        fetchone=True,
    )

    recent_sessions = query(
        """
        SELECT
            r.username,
            COUNT(*) AS sessions,
            SUM(COALESCE(r.acctinputoctets, 0) + COALESCE(r.acctoutputoctets, 0)) AS total_bytes,
            MAX(r.acctstarttime) AS last_start
        FROM radacct r
        WHERE r.username LIKE %s
        GROUP BY r.username
        ORDER BY last_start DESC
        LIMIT %s
        """,
        (like_value, limit),
    )

    last_auth = query(
        """
        SELECT
            p.username,
            p.reply,
            p.authdate
        FROM radpostauth p
        WHERE p.username LIKE %s
        ORDER BY p.authdate DESC
        LIMIT %s
        """,
        (like_value, limit),
    )

    return {
        "filter_prefix": prefix or None,
        "totals": {
            "total_users": int(totals["total_users"] if totals and totals["total_users"] is not None else 0),
            "total_vouchers": int(totals["total_vouchers"] if totals and totals["total_vouchers"] is not None else 0),
        },
        "recent_sessions": recent_sessions,
        "last_auth_attempts": last_auth,
    }
