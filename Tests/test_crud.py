import json
import os
import shutil
import uuid

import pytest
from PyQt6.QtWidgets import QApplication
from sqlalchemy import inspect

from Business.crypto_service import (
    CryptoManagerService,
    CryptoServiceError,
    FileManagementService,
    HashService,
    KeyManagementService,
    PerformanceMetricCalculator,
)
from Business.lab_algorithms import base64_lab
from Model.models import BASE_DIR, app, db, ensure_runtime_directories, init_db, seed_defaults
from Presenter.kms_window import KMSWindow
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.key_repo import KeyRepository
from Repositories.operation_repo import OperationRepository
from Repositories.performance_repo import PerformanceRepository


os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


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
    path = os.path.join(temp_root, unique_name("kms_test"))
    os.makedirs(path, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="module")
def qt_app():
    app_instance = QApplication.instance() or QApplication([])
    yield app_instance


def write_sample_file(sandbox_dir, name, content):
    file_path = os.path.join(sandbox_dir, name)
    with open(file_path, "wb") as handle:
        handle.write(content)
    return file_path


def framework_by_name(name):
    return FrameworkRepository.get_by_name(name)


def algorithm_by_name(name):
    return AlgorithmRepository.get_by_name(name)


def roundtrip(algorithm_name, framework_name, file_path, key_name):
    framework = framework_by_name(framework_name)
    algorithm = algorithm_by_name(algorithm_name)
    managed_file = FileManagementService.register_file(file_path)
    key_record = KeyManagementService.generate_key(key_name, algorithm, framework)
    encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
    decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)
    refreshed_file = FileRepository.get_by_id(managed_file.id)
    return key_record, encrypt_result, decrypt_result, refreshed_file


def test_database_creation_works():
    init_db(seed=True)
    with app.app_context():
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
        performance_columns = {column["name"] for column in inspector.get_columns("performances")}
        operation_columns = {column["name"] for column in inspector.get_columns("crypto_operations")}
    assert {
        "frameworks",
        "algorithms",
        "keys",
        "managed_files",
        "crypto_operations",
        "performances",
    }.issubset(table_names)
    assert {"time_per_byte_ms", "time_per_byte_us", "throughput_bytes_per_second", "throughput_mib_per_second"}.issubset(performance_columns)
    assert {"encrypted_data_key", "iv_nonce", "auth_tag", "key_wrap_algorithm", "data_encryption_algorithm", "operation_metadata_json"}.issubset(operation_columns)


def test_default_frameworks_and_algorithms_exist():
    with app.app_context():
        frameworks = {framework.name for framework in FrameworkRepository.get_all()}
        algorithms = {algorithm.name for algorithm in AlgorithmRepository.get_all()}
        lab_framework = FrameworkRepository.get_by_name("Lab Educational")
        cryptography_framework = FrameworkRepository.get_by_name("Cryptography")
        legacy_framework = FrameworkRepository.get_by_name("Custom Educational / Legacy")
    assert frameworks == {"OpenSSL", "Cryptography", "Lab Educational"}
    assert algorithms == {
        "AES-256-CBC",
        "AES-256-GCM",
        "DES-CBC",
        "RSA-2048",
        "DES-LAB",
        "RSA-LAB",
    }
    assert legacy_framework is None
    assert "performance comparison with OpenSSL" in lab_framework.description
    assert cryptography_framework.display_name == "Python cryptography"


def test_framework_crud():
    with app.app_context():
        framework = FrameworkRepository.create(unique_name("Framework"), "Custom impl", "1.0")
        assert FrameworkRepository.get_by_id(framework.id).name == framework.name
        assert FrameworkRepository.update(framework.id, version="1.1").version == "1.1"
        assert FrameworkRepository.delete(framework.id) is True


def test_algorithm_crud():
    with app.app_context():
        algorithm = AlgorithmRepository.create(unique_name("Algo"), "symmetric", 64, mode="CBC", description="test")
        assert AlgorithmRepository.get_by_id(algorithm.id).name == algorithm.name
        assert AlgorithmRepository.update(algorithm.id, description="updated").description == "updated"
        assert AlgorithmRepository.delete(algorithm.id) is True


def test_key_crud():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Lab Educational")
        algorithm = AlgorithmRepository.get_by_name("DES-LAB")
        key_record = KeyRepository.create(
            name=unique_name("key"),
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_type="symmetric",
            key_value="ZmFrZV9rZXk=",
        )
        assert KeyRepository.get_by_id(key_record.id).name == key_record.name
        assert KeyRepository.update(key_record.id, is_active=False).is_active is False
        assert KeyRepository.delete(key_record.id) is True


def test_managed_file_crud_uses_internal_hash_service(sandbox_dir):
    original_path = write_sample_file(sandbox_dir, "crud.txt", b"crud-data")
    with app.app_context():
        managed_file = FileRepository.create(
            original_name="crud.txt",
            original_path=original_path,
            original_hash=HashService.sha256_for_file(original_path),
        )
        assert FileRepository.get_by_id(managed_file.id).original_name == "crud.txt"
        assert managed_file.original_hash == "1932aa14f7a3c2e4e80c398dd657075025ec2e5652738081ffddca1632548bfa"
        assert FileRepository.update(managed_file.id, status="encrypted", encrypted_path="enc.bin").status == "encrypted"
        assert FileRepository.delete(managed_file.id) is True


def test_operation_and_performance_crud(sandbox_dir):
    original_path = write_sample_file(sandbox_dir, "op.txt", b"operation-data")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        key_record = KeyRepository.create(
            name=unique_name("perfkey"),
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_type="symmetric",
            key_value="ZmFrZV9rZXk=",
        )
        managed_file = FileRepository.create(
            original_name="op.txt",
            original_path=original_path,
            original_hash=HashService.sha256_for_file(original_path),
        )
        operation = OperationRepository.create(
            file_id=managed_file.id,
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_id=key_record.id,
            operation_type="encrypt",
            status="running",
        )
        assert OperationRepository.get_by_id(operation.id).status == "running"
        assert OperationRepository.update(operation.id, status="success", notes="ok").status == "success"
        performance = PerformanceRepository.create(operation.id, 12.5, 1.2, 100, 120, 0.125, 125.0, 8000.0, 0.0076)
        assert PerformanceRepository.get_by_id(performance.id).operation_id == operation.id
        assert PerformanceRepository.get_by_id(performance.id).time_per_byte_us == 125.0
        assert PerformanceRepository.delete(performance.id) is True
        assert OperationRepository.delete(operation.id) is True


def test_duplicate_registration_reuses_same_managed_file(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "duplicate.txt", b"duplicate-data")
    with app.app_context():
        first = FileManagementService.register_file(input_path)
        second = FileManagementService.register_file(input_path)
        all_files = FileRepository.get_all()
    assert first.id == second.id
    assert len(all_files) == 1
    assert os.path.exists(second.original_path)


def test_duplicate_registration_preserves_processed_state_when_file_is_unchanged(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "duplicate_processed.txt", b"duplicate-processed-data")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("dup_aes"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, key_record)
        refreshed_before = FileRepository.get_by_id(managed_file.id)
        before_snapshot = (
            refreshed_before.status,
            refreshed_before.encrypted_path,
            refreshed_before.decrypted_path,
            refreshed_before.integrity_verified,
        )
        refreshed_after = FileManagementService.register_file(input_path)
        after_snapshot = (
            refreshed_after.status,
            refreshed_after.encrypted_path,
            refreshed_after.decrypted_path,
            refreshed_after.integrity_verified,
        )
    assert before_snapshot[0] == "decrypted"
    assert after_snapshot[0] == "decrypted"
    assert after_snapshot[1] == before_snapshot[1]
    assert after_snapshot[2] == before_snapshot[2]
    assert after_snapshot[3] is True


def test_key_management_uses_base64_lab_for_des_lab_keys():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Lab Educational")
        algorithm = AlgorithmRepository.get_by_name("DES-LAB")
        key_record = KeyManagementService.generate_key(unique_name("lab_des_key"), algorithm, framework)
        decoded = KeyManagementService.decode_symmetric_key(key_record)
        encoded_value = key_record.key_value

    assert len(decoded) == 8
    assert encoded_value == base64_lab.encode_base64_bytes(decoded)


def test_rsa_lab_key_generation_stores_json_parameters():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Lab Educational")
        algorithm = AlgorithmRepository.get_by_name("RSA-LAB")
        key_record = KeyManagementService.generate_key(unique_name("lab_rsa_key"), algorithm, framework)
        payload = json.loads(key_record.key_value)
    assert payload["n"] == 3233
    assert payload["e"] == 17
    assert payload["d"] == 2753


def test_performance_calculations_include_normalized_metrics():
    metrics = PerformanceMetricCalculator.calculate(50.0, 2.5, 1000, 1200)
    assert metrics.time_per_byte_ms == pytest.approx(0.05)
    assert metrics.time_per_byte_us == pytest.approx(50.0)
    assert metrics.throughput_bytes_per_second == pytest.approx(20000.0)
    assert metrics.throughput_mib_per_second == pytest.approx(20000.0 / (1024 * 1024))


def test_aes_openssl_encrypt_decrypt_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "openssl_aes.txt", b"OpenSSL AES test content")
    with app.app_context():
        _, _, decrypt_result, refreshed_file = roundtrip(
            "AES-256-CBC",
            "OpenSSL",
            input_path,
            unique_name("openssl_aes_key"),
        )
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True


def test_des_openssl_encrypt_decrypt_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "openssl_des.txt", b"OpenSSL DES test content")
    with app.app_context():
        _, encrypt_result, decrypt_result, refreshed_file = roundtrip(
            "DES-CBC",
            "OpenSSL",
            input_path,
            unique_name("openssl_des_key"),
        )
        encrypt_perf = PerformanceRepository.get_by_operation_id(encrypt_result.operation.id)
        decrypt_perf = PerformanceRepository.get_by_operation_id(decrypt_result.operation.id)
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert encrypt_perf is not None
    assert decrypt_perf is not None


def test_aes_cryptography_cbc_encrypt_decrypt_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "cryptography_aes_cbc.txt", b"Cryptography AES CBC test content")
    with app.app_context():
        _, encrypt_result, decrypt_result, refreshed_file = roundtrip(
            "AES-256-CBC",
            "Cryptography",
            input_path,
            unique_name("cryptography_aes_cbc_key"),
        )
        encrypt_perf = PerformanceRepository.get_by_operation_id(encrypt_result.operation.id)
        decrypt_perf = PerformanceRepository.get_by_operation_id(decrypt_result.operation.id)
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert encrypt_perf is not None
    assert decrypt_perf is not None


def test_aes_cryptography_gcm_encrypt_decrypt_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "cryptography_aes_gcm.txt", b"Cryptography AES GCM test content")
    with app.app_context():
        _, encrypt_result, decrypt_result, refreshed_file = roundtrip(
            "AES-256-GCM",
            "Cryptography",
            input_path,
            unique_name("cryptography_aes_gcm_key"),
        )
        encrypt_operation = OperationRepository.get_by_id(encrypt_result.operation.id)
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert encrypt_operation.iv_nonce is not None
    assert encrypt_operation.auth_tag is not None


def test_rsa_cryptography_encrypt_decrypt_small_demo_file_works(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "small_crypto_rsa.txt", b"small cryptography rsa demo")
    with app.app_context():
        _, _, decrypt_result, refreshed_file = roundtrip(
            "RSA-2048",
            "Cryptography",
            input_path,
            unique_name("cryptography_rsa_key"),
        )
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True


def test_cryptography_aes_gcm_wrong_key_fails_clearly(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "gcm_wrong_key.txt", b"gcm wrong key")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        managed_file = FileManagementService.register_file(input_path)
        correct_key = KeyManagementService.generate_key(unique_name("gcm_ok"), algorithm, framework)
        wrong_key = KeyManagementService.generate_key(unique_name("gcm_bad"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, correct_key)
        with pytest.raises(CryptoServiceError, match="AES-GCM integrity verification failed"):
            CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, wrong_key)


def test_cryptography_aes_gcm_tampered_ciphertext_fails_clearly(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "gcm_tamper.txt", b"gcm tamper")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("gcm_tamper"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        with open(encrypted.output_path, "rb") as handle:
            payload = bytearray(handle.read())
        payload[0] ^= 1
        with open(encrypted.output_path, "wb") as handle:
            handle.write(payload)
        with pytest.raises(CryptoServiceError, match="AES-GCM integrity verification failed"):
            CryptoManagerService.decrypt_file(FileRepository.get_by_id(managed_file.id), algorithm, framework, key_record)


def test_rsa_openssl_encrypt_decrypt_small_demo_file_works(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "small_rsa.txt", b"small rsa demo")
    with app.app_context():
        _, _, decrypt_result, refreshed_file = roundtrip(
            "RSA-2048",
            "OpenSSL",
            input_path,
            unique_name("openssl_rsa_key"),
        )
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True


def test_lab_des_roundtrip_creates_performance_record(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "lab_des.txt", b"Lab DES integration test")
    with app.app_context():
        _, encrypt_result, decrypt_result, refreshed_file = roundtrip(
            "DES-LAB",
            "Lab Educational",
            input_path,
            unique_name("lab_des_key"),
        )
        encrypt_perf = PerformanceRepository.get_by_operation_id(encrypt_result.operation.id)
        decrypt_perf = PerformanceRepository.get_by_operation_id(decrypt_result.operation.id)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert encrypt_perf is not None
    assert decrypt_perf is not None


def test_lab_rsa_roundtrip_creates_performance_record(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "lab_rsa.txt", b"Lab RSA integration")
    with app.app_context():
        _, encrypt_result, decrypt_result, refreshed_file = roundtrip(
            "RSA-LAB",
            "Lab Educational",
            input_path,
            unique_name("lab_rsa_key"),
        )
        encrypt_perf = PerformanceRepository.get_by_operation_id(encrypt_result.operation.id)
        decrypt_perf = PerformanceRepository.get_by_operation_id(decrypt_result.operation.id)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert encrypt_perf is not None
    assert decrypt_perf is not None


def test_invalid_framework_algorithm_combination_is_rejected(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "invalid.txt", b"invalid combo")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Lab Educational")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        managed_file = FileManagementService.register_file(input_path)
        lab_des_key = KeyManagementService.generate_key(unique_name("labdes"), AlgorithmRepository.get_by_name("DES-LAB"), framework)
        with pytest.raises(CryptoServiceError, match="Unsupported framework/algorithm combination"):
            CryptoManagerService.encrypt_file(managed_file, algorithm, framework, lab_des_key)


def test_rsa_large_file_rejection_is_recorded_as_failed_operation(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "large_rsa.txt", b"x" * 256)
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("RSA-2048")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("rsa_large"), algorithm, framework)
        with pytest.raises(CryptoServiceError, match="small demo files"):
            CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        refreshed_file = FileRepository.get_by_id(managed_file.id)
        latest_operation = OperationRepository.get_all()[0]
    assert refreshed_file.status == "failed"
    assert latest_operation.status == "failed"


def test_compatible_key_filtering_for_main_workflow():
    with app.app_context():
        openssl = FrameworkRepository.get_by_name("OpenSSL")
        cryptography = FrameworkRepository.get_by_name("Cryptography")
        lab = FrameworkRepository.get_by_name("Lab Educational")
        aes = AlgorithmRepository.get_by_name("AES-256-CBC")
        aes_gcm = AlgorithmRepository.get_by_name("AES-256-GCM")
        rsa = AlgorithmRepository.get_by_name("RSA-2048")
        des_lab = AlgorithmRepository.get_by_name("DES-LAB")
        rsa_lab = AlgorithmRepository.get_by_name("RSA-LAB")

        openssl_aes_key = KeyManagementService.generate_key(unique_name("aes"), aes, openssl)
        cryptography_aes_key = KeyManagementService.generate_key(unique_name("crypto_aes"), aes, cryptography)
        cryptography_aes_gcm_key = KeyManagementService.generate_key(unique_name("crypto_gcm"), aes_gcm, cryptography)
        cryptography_rsa_key = KeyManagementService.generate_key(unique_name("crypto_rsa"), rsa, cryptography)
        lab_des_key = KeyManagementService.generate_key(unique_name("des_lab"), des_lab, lab)
        lab_rsa_key = KeyManagementService.generate_key(unique_name("rsa_lab"), rsa_lab, lab)

        openssl_keys = KeyRepository.get_compatible_active_keys_paginated(openssl.id, aes, 1, 10)
        cryptography_aes_keys = KeyRepository.get_compatible_active_keys_paginated(cryptography.id, aes, 1, 10)
        cryptography_aes_gcm_keys = KeyRepository.get_compatible_active_keys_paginated(cryptography.id, aes_gcm, 1, 10)
        cryptography_rsa_keys = KeyRepository.get_compatible_active_keys_paginated(cryptography.id, rsa, 1, 10)
        lab_des_keys = KeyRepository.get_compatible_active_keys_paginated(lab.id, des_lab, 1, 10)
        lab_rsa_keys = KeyRepository.get_compatible_active_keys_paginated(lab.id, rsa_lab, 1, 10)

    assert [item.id for item in openssl_keys] == [openssl_aes_key.id]
    assert [item.id for item in cryptography_aes_keys] == [cryptography_aes_key.id]
    assert [item.id for item in cryptography_aes_gcm_keys] == [cryptography_aes_gcm_key.id]
    assert [item.id for item in cryptography_rsa_keys] == [cryptography_rsa_key.id]
    assert [item.id for item in lab_des_keys] == [lab_des_key.id]
    assert [item.id for item in lab_rsa_keys] == [lab_rsa_key.id]


def test_main_ui_hides_demo_lab_box_and_shows_integrated_frameworks(qt_app):
    with app.app_context():
        window = KMSWindow()
        algorithm_items = [window.combo_alg.itemText(index) for index in range(window.combo_alg.count())]
        default_framework_items = [window.combo_fw.itemText(index) for index in range(window.combo_fw.count())]
        gcm_algorithm_index = next(
            index for index in range(window.combo_alg.count()) if window.combo_alg.itemText(index).startswith("AES-256-GCM")
        )
        window.combo_alg.setCurrentIndex(gcm_algorithm_index)
        gcm_framework_items = [window.combo_fw.itemText(index) for index in range(window.combo_fw.count())]
        lab_algorithm_index = next(
            index for index in range(window.combo_alg.count()) if window.combo_alg.itemText(index).startswith("DES-LAB")
        )
        window.combo_alg.setCurrentIndex(lab_algorithm_index)
        lab_framework_items = [window.combo_fw.itemText(index) for index in range(window.combo_fw.count())]

    assert not hasattr(window, "btn_lab_sha256")
    assert not hasattr(window, "btn_lab_hmac")
    assert not hasattr(window, "btn_lab_b64_encode")
    assert not hasattr(window, "btn_lab_b64_decode")
    assert not hasattr(window, "btn_lab_signature")
    assert "OpenSSL" in default_framework_items
    assert "Python cryptography" in default_framework_items
    assert gcm_framework_items == ["Python cryptography"]
    assert "Lab Educational" in lab_framework_items
    assert window.framework_badge.text() == "Frameworks: 3"
    assert window.algorithm_badge.text() == "Algorithms: 6"
    assert any(item.startswith("AES-256-GCM") for item in algorithm_items)
    assert any(item.startswith("DES-LAB") for item in algorithm_items)
    assert any(item.startswith("RSA-LAB") for item in algorithm_items)
    assert not any("Hybrid RSA-AES" in item for item in algorithm_items)
    assert not any("BASE64-LAB" in item or "HMAC-SHA1-LAB" in item or "DIGITAL-SIGNATURE-LAB" in item for item in algorithm_items)
    window.close()
