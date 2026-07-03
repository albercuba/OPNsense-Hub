import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CompanyUser, User

ROLE_ORDER = {"viewer": 1, "admin": 2, "owner": 3}


def is_global_admin(user: User) -> bool:
    return user.role == "administrator"


def get_company_role(db: Session, user: User, company_id: uuid.UUID) -> str | None:
    return db.scalar(
        select(CompanyUser.role).where(
            CompanyUser.user_id == user.id, CompanyUser.company_id == company_id
        )
    )


def has_company_role(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> bool:
    role = get_company_role(db, user, company_id)
    return role is not None and ROLE_ORDER.get(role, 0) >= ROLE_ORDER[minimum]


def has_company_access(
    db: Session, user: User, company_id: uuid.UUID, minimum: str = "viewer"
) -> bool:
    return is_global_admin(user) or has_company_role(db, user, company_id, minimum)
