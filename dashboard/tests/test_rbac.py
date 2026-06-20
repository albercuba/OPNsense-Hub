from app.rbac import ROLE_ORDER


def test_role_order():
    assert ROLE_ORDER["owner"] > ROLE_ORDER["admin"] > ROLE_ORDER["viewer"]
