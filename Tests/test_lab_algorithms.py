import os
import shutil
import uuid

import pytest

from Business.lab_algorithms import base64_lab, des_lab, hash_lab, modular_arithmetic_lab, rsa_lab, signature_pki_lab
from Model.models import BASE_DIR, app, db, ensure_runtime_directories, seed_defaults
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.framework_repo import FrameworkRepository


def unique_name(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def runtime_data_dirs():
    return (
        os.path.join(BASE_DIR, "data", "original"),
        os.path.join(BASE_DIR, "data", "encrypted"),
        os.path.join(BASE_DIR, "data", "decrypted"),
        os.path.join(BASE_DIR, "data", "keys"),
        os.path.join(BASE_DIR, "data", "test_tmp"),
    )


def clean_runtime_files():
    for path in runtime_data_dirs():
        os.makedirs(path, exist_ok=True)
        for entry in os.listdir(path):
            if entry == ".gitkeep":
                continue
            full_path = os.path.join(path, entry)
            if os.path.isdir(full_path):
                shutil.rmtree(full_path, ignore_errors=True)
            else:
                os.remove(full_path)


@pytest.fixture(autouse=True)
def clean_database():
    ensure_runtime_directories()
    clean_runtime_files()
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_defaults()
        yield
        db.session.remove()
    clean_runtime_files()


@pytest.fixture
def sandbox_dir():
    temp_root = os.path.join(BASE_DIR, "data", "test_tmp")
    os.makedirs(temp_root, exist_ok=True)
    path = os.path.join(temp_root, unique_name("lab_test"))
    os.makedirs(path, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def write_sample_file(sandbox_dir, name, content):
    file_path = os.path.join(sandbox_dir, name)
    with open(file_path, "wb") as handle:
        handle.write(content)
    return file_path


def test_des_lab_encrypt_decrypt_bytes_returns_original_plaintext():
    plaintext = b"DES lab bytes test"
    key = b"lab-key!"
    ciphertext = des_lab.encrypt_bytes(plaintext, key)
    assert ciphertext != plaintext
    assert des_lab.decrypt_bytes(ciphertext, key) == plaintext


def test_des_lab_encrypt_decrypt_file_returns_original_file_content(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "des_plain.txt", b"DES lab file test")
    encrypted_path = os.path.join(sandbox_dir, "des.enc")
    decrypted_path = os.path.join(sandbox_dir, "des.dec.txt")
    des_lab.encrypt_file(input_path, encrypted_path, b"secret!!")
    des_lab.decrypt_file(encrypted_path, decrypted_path, b"secret!!")
    with open(decrypted_path, "rb") as handle:
        assert handle.read() == b"DES lab file test"


def test_rsa_lab_encrypt_decrypt_bytes_returns_original_data():
    key_pair = rsa_lab.generate_demo_key_pair()
    plaintext = b"RSA"
    encrypted = rsa_lab.rsa_encrypt_bytes(plaintext, key_pair.e, key_pair.n)
    assert rsa_lab.rsa_decrypt_bytes(encrypted, key_pair.d, key_pair.n) == plaintext


def test_rsa_lab_encrypt_decrypt_file_returns_original_file_content(sandbox_dir):
    key_pair = rsa_lab.generate_demo_key_pair()
    input_path = write_sample_file(sandbox_dir, "rsa_plain.txt", b"Hello Lab RSA")
    encrypted_path = os.path.join(sandbox_dir, "rsa.enc.txt")
    decrypted_path = os.path.join(sandbox_dir, "rsa.dec.txt")
    rsa_lab.rsa_encrypt_file(input_path, encrypted_path, key_pair.e, key_pair.n)
    rsa_lab.rsa_decrypt_file(encrypted_path, decrypted_path, key_pair.d, key_pair.n)
    with open(decrypted_path, "rb") as handle:
        assert handle.read() == b"Hello Lab RSA"


def test_rsa_lab_encrypt_bytes_rejects_invalid_small_modulus():
    with pytest.raises(ValueError, match="n must be greater than 255"):
        rsa_lab.rsa_encrypt_bytes(b"A", 17, 255)


def test_sha1_returns_expected_value_for_abc():
    assert hash_lab.sha1(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_sha256_returns_expected_value_for_abc():
    assert hash_lab.sha256(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hmac_sha1_returns_stable_deterministic_value():
    value = hash_lab.hmac_sha1(b"key", b"abc")
    assert value == hash_lab.hmac_sha1(b"key", b"abc")
    assert value == "4fd0b215276ef12f2b3e4c8ecac2811498b656fc"


def test_base64_encode_decode_returns_original_bytes():
    raw = b"\x00\x01\xfflab-bytes"
    encoded = base64_lab.encode_base64_bytes(raw)
    assert base64_lab.decode_base64_bytes(encoded) == raw


def test_base64_file_encode_decode_returns_original_bytes(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "base64.bin", b"\x00\x01\xfflab-bytes")
    encoded_path = os.path.join(sandbox_dir, "base64.txt")
    decoded_path = os.path.join(sandbox_dir, "decoded.bin")
    base64_lab.encode_file_to_base64(input_path, encoded_path)
    base64_lab.decode_file_from_base64(encoded_path, decoded_path)
    with open(decoded_path, "rb") as handle:
        assert handle.read() == b"\x00\x01\xfflab-bytes"


def test_digital_signature_verification_returns_true_for_unchanged_message():
    key_pair = rsa_lab.generate_demo_key_pair()
    pki = signature_pki_lab.PKISystem(key_pair.n, key_pair.e, key_pair.d)
    certificate = signature_pki_lab.CertificateAuthority("Lab CA").issue_certificate("User", (key_pair.n, key_pair.e))
    signed_doc = pki.create_signed_doc("Confidential Data")
    assert pki.verify_with_cert(signed_doc, certificate) is True


def test_digital_signature_verification_returns_false_after_tampering_message():
    key_pair = rsa_lab.generate_demo_key_pair()
    pki = signature_pki_lab.PKISystem(key_pair.n, key_pair.e, key_pair.d)
    certificate = signature_pki_lab.CertificateAuthority("Lab CA").issue_certificate("User", (key_pair.n, key_pair.e))
    signed_doc = pki.create_signed_doc("Confidential Data")
    tampered_doc = signature_pki_lab.SignedDocument(
        m="Tampered Data",
        s=signed_doc.s,
        hash_algo=signed_doc.hash_algo,
        timestamp=signed_doc.timestamp,
    )
    assert pki.verify_with_cert(tampered_doc, certificate) is False


def test_modular_exponentiation_returns_expected_value():
    assert modular_arithmetic_lab.power_modular(289, 11, 1363) == 318


def test_lab_educational_framework_and_algorithms_exist_after_seed():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Lab Educational")
        des_algorithm = AlgorithmRepository.get_by_name("DES-LAB")
        rsa_algorithm = AlgorithmRepository.get_by_name("RSA-LAB")
    assert framework is not None
    assert des_algorithm is not None
    assert rsa_algorithm is not None
