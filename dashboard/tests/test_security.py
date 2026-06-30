from app.security import (
    generate_totp_secret,
    hash_secret,
    hash_session_token,
    password_is_strong_enough,
    random_otp,
    totp_code,
    totp_provisioning_uri,
    verify_secret,
    verify_totp_code,
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


def test_totp_secret_and_uri_are_generated_in_expected_format():
    secret = generate_totp_secret()
    assert len(secret) >= 32
    assert secret.isalnum()
    assert totp_provisioning_uri(secret, "user@example.com").startswith(
        "otpauth://totp/"
    )


def test_totp_code_verifies_with_current_and_adjacent_window():
    secret = "JBSWY3DPEHPK3PXP"
    code = totp_code(secret, for_time=1700000000)
    assert verify_totp_code(secret, code, for_time=1700000000)
    assert verify_totp_code(secret, code, for_time=1700000029)
    assert not verify_totp_code(secret, code, for_time=1700000065)
