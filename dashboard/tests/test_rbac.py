from uuid import uuid4

import pytest
from app.database import Base
from app.models import Company, CompanyUser, User
from app.rbac import ROLE_ORDER, has_company_access
from app.routers.companies import create_company
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


def test_role_order():
    assert ROLE_ORDER["owner"] > ROLE_ORDER["admin"] > ROLE_ORDER["viewer"]


def test_non_admin_cannot_create_company_via_api_handler():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/companies",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )
    user = User(id=uuid4(), email="user@example.com", password_hash="hash", role="user")

    with pytest.raises(HTTPException) as exc_info:
        create_company(request, None, user, "Acme")  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403


def test_viewer_access_requires_company_membership():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        company = Company(id=uuid4(), name="Acme")
        member = User(id=uuid4(), email="member@example.com", password_hash="hash")
        outsider = User(id=uuid4(), email="outsider@example.com", password_hash="hash")
        admin = User(
            id=uuid4(),
            email="admin@example.com",
            password_hash="hash",
            role="administrator",
        )
        session.add_all([company, member, outsider, admin])
        session.flush()
        session.add(
            CompanyUser(company_id=company.id, user_id=member.id, role="viewer")
        )
        session.commit()

        assert has_company_access(session, member, company.id, "viewer") is True
        assert has_company_access(session, outsider, company.id, "viewer") is False
        assert has_company_access(session, admin, company.id, "viewer") is True
    finally:
        session.close()
        engine.dispose()
