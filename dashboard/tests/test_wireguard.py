import pytest
from app.wireguard import WireGuardError, validate_public_key


def test_validate_public_key_accepts_wireguard_shape():
    validate_public_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")


def test_validate_public_key_rejects_shell_input():
    with pytest.raises(WireGuardError):
        validate_public_key("bad; rm -rf /")
