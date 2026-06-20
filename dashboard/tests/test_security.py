from app.security import hash_secret, random_otp, verify_secret


def test_hash_secret_roundtrip():
    encoded = hash_secret("secret-value")
    assert encoded != "secret-value"
    assert verify_secret("secret-value", encoded)
    assert not verify_secret("wrong", encoded)


def test_random_otp_shape():
    otp = random_otp()
    assert len(otp) == 9
    assert otp[4] == "-"
