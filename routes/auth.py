import subprocess
from fastapi import APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends
from core.config import settings
from core.security import create_access_token

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])


def authenticate_ad(username: str, password: str) -> bool:
    """Valida credenciales contra Active Directory via ntlm_auth."""
    try:
        result = subprocess.run(
            [
                "/usr/bin/ntlm_auth",
                "--request-nt-key",
                f"--domain=AXIO",
                f"--username={username}",
                f"--password={password}",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def authenticate_local(username: str, password: str) -> bool:
    """Valida credenciales locales desde el .env (fallback)."""
    return (
        username == settings.GUI_ADMIN_USER
        and password == settings.GUI_ADMIN_PASSWORD
    )


@router.post("/login", summary="Login del panel de administración")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Autentica al administrador del panel.
    Primero intenta contra Active Directory, si falla usa credenciales locales.
    """
    username = form_data.username
    password = form_data.password

    # 1. Intentar autenticación contra AD
    ad_ok = authenticate_ad(username, password)

    # 2. Si AD falla, intentar con credenciales locales del .env
    if not ad_ok:
        local_ok = authenticate_local(username, password)
        if not local_ok:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario o contraseña incorrectos",
            )
        # Login local exitoso
        token = create_access_token({
            "sub": username,
            "role": "admin",
            "auth_method": "local"
        })
        return {"access_token": token, "token_type": "bearer"}

    # Login AD exitoso
    token = create_access_token({
        "sub": username,
        "role": "admin",
        "auth_method": "active_directory"
    })
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", summary="Info del usuario autenticado")
def me(payload: dict = Depends(
    __import__("core.security", fromlist=["verify_token"]).verify_token
)):
    return {
        "username": payload.get("sub"),
        "role": payload.get("role"),
        "auth_method": payload.get("auth_method", "local")
    }
