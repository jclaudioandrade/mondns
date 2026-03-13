from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.core.deps import require_api_admin
from app.core.security import hash_password
from app.core.audit import log_action, get_client_ip
from app.models.user import User

router = APIRouter(prefix="/users", tags=["users"])


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    full_name: str | None = None
    password: str
    group_name: str = "analyst"

    @field_validator("group_name")
    @classmethod
    def validate_group(cls, v):
        if v not in ("admin", "analyst"):
            raise ValueError("Grupo deve ser 'admin' ou 'analyst'.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Senha deve ter pelo menos 8 caracteres.")
        return v


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    group_name: str | None = None
    is_active: bool | None = None
    password: str | None = None


@router.get("")
def list_users(db: Session = Depends(get_db), _=Depends(require_api_admin)):
    users = db.query(User).order_by(User.username).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email,
         "full_name": u.full_name, "group_name": u.group_name,
         "is_active": u.is_active, "last_login": u.last_login,
         "created_at": u.created_at}
        for u in users
    ]


@router.post("", status_code=201)
def create_user(
    data: UserCreate, request: Request,
    db: Session = Depends(get_db), user=Depends(require_api_admin),
):
    if db.query(User).filter(User.username == data.username).first():
        raise HTTPException(status_code=400, detail="Usuário já existe.")
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado.")

    new_user = User(
        username=data.username, email=data.email, full_name=data.full_name,
        password_hash=hash_password(data.password), group_name=data.group_name,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_action(db, "user_created", username=user["username"], user_id=user["id"],
               resource_type="user", resource_id=new_user.id,
               details={"new_username": data.username, "group": data.group_name},
               ip_address=get_client_ip(request))
    return {"id": new_user.id, "username": new_user.username}


@router.put("/{user_id}")
def update_user(
    user_id: int, data: UserUpdate, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    changes: dict = {}
    if data.email is not None:
        changes["email"] = data.email
        u.email = data.email
    if data.full_name is not None:
        u.full_name = data.full_name
    if data.group_name is not None:
        if data.group_name not in ("admin", "analyst"):
            raise HTTPException(status_code=400, detail="Grupo inválido.")
        changes["group"] = data.group_name
        u.group_name = data.group_name
    if data.is_active is not None:
        changes["is_active"] = data.is_active
        u.is_active = data.is_active
    if data.password is not None:
        if len(data.password) < 8:
            raise HTTPException(status_code=400, detail="Senha muito curta.")
        u.password_hash = hash_password(data.password)
        changes["password"] = "alterada"

    db.commit()
    log_action(db, "user_updated", username=admin["username"], user_id=admin["id"],
               resource_type="user", resource_id=user_id,
               details=changes, ip_address=get_client_ip(request))
    return {"ok": True}


@router.delete("/{user_id}", status_code=204)
def delete_user(
    user_id: int, request: Request,
    db: Session = Depends(get_db), admin=Depends(require_api_admin),
):
    if admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="Não é possível excluir seu próprio usuário.")
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    db.delete(u)
    db.commit()
    log_action(db, "user_deleted", username=admin["username"], user_id=admin["id"],
               resource_type="user", resource_id=user_id,
               ip_address=get_client_ip(request))
