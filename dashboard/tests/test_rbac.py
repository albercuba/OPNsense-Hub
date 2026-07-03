from uuid import uuid4

from app.database import Base
from app.models import Company, CompanyUser, User
from app.rbac import ROLE_ORDER, has_company_access
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@compiles(INET, "sqlite")
def compile_inet_sqlite(_type, _compiler, **_kw):
    return "TEXT"


def test_role_order():
    assert ROLE_ORDER["owner"] > ROLE_ORDER["admin"] > ROLE_ORDER["viewer"]


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
