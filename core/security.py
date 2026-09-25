from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from core.config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_token(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token invalido o expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception


def require_role(allowed_roles: list[str]):
    """
    Dependencia FastAPI que verifica rol en el JWT.

    Roles disponibles:
        admin    -> acceso total
        config   -> gestion operativa, sin configuracion critica del sistema
        helpdesk -> solo registro de MACs (Calling-Station-Id)
    """
    def dependency(token: str = Depends(oauth2_scheme)) -> dict:
        exc_unauth = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalido o expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            if payload.get("sub") is None:
                raise exc_unauth
        except JWTError:
            raise exc_unauth

        role = payload.get("role", "")
        if role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acceso denegado. Rol requerido: {', '.join(allowed_roles)}. Tu rol: {role}",
            )
        return payload
    return dependency


# Shortcuts para usar en rutas.
require_admin = require_role(["admin"])
require_config = require_role(["admin", "config"])
require_helpdesk = require_role(["admin", "config", "helpdesk"])
require_viewer = require_helpdesk
