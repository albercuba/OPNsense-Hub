from app.security import (
    hash_secret,
    hash_session_token,
    password_is_strong_enough,
    random_otp,
    verify_secret,
)


def test_hash_secret_roundtrip():
    encoded = hash_secret("secret-value")
    assert encoded != "secret-value"
    assert verify_secret("secret-value", encoded)
    assert not verify_secret("wrong", encoded)


def test_random_otp_shape():
    otp = random_otp()
    assert len(otp) == 9
    assert otp[4] == "-"


def test_hash_session_token_is_deterministic_for_same_secret():
    token_hash = hash_session_token("secret-key", "session-token")
    assert token_hash == hash_session_token("secret-key", "session-token")
    assert token_hash != hash_session_token("different-secret", "session-token")


def test_password_strength_check_requires_length_letters_and_numbers():
    assert password_is_strong_enough("StrongPassword123")
    assert not password_is_strong_enough("short")
    assert not password_is_strong_enough("allletterslong")
