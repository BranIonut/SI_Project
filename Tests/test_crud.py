import hashlib
import os
import shutil
import uuid
import base64
import json

import pytest
from sqlalchemy import inspect

from Business.crypto_service import (
    CryptoManagerService,
    CryptoServiceError,
    FileManagementService,
    HashService,
    KeyManagementService,
    PerformanceMetricCalculator,
)
from Model.models import BASE_DIR, app, db, ensure_runtime_directories, init_db, seed_defaults
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.key_repo import KeyRepository
from Repositories.operation_repo import OperationRepository
from Repositories.performance_repo import PerformanceRepository


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


def write_sample_file(sandbox_dir, name, content):
    file_path = os.path.join(sandbox_dir, name)
    with open(file_path, "wb") as handle:
        handle.write(content)
    return file_path


def framework_by_name(name):
    with app.app_context():
        return FrameworkRepository.get_by_name(name)


def algorithm_by_name(name):
    with app.app_context():
        return AlgorithmRepository.get_by_name(name)


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
        cryptography_fw = FrameworkRepository.get_by_name("Cryptography")
    assert frameworks == {"OpenSSL", "Cryptography", "Custom Educational"}
    assert {"AES-256-CBC", "AES-256-GCM", "DES-CBC", "RSA-2048", "Hybrid RSA-AES"}.issubset(algorithms)
    assert cryptography_fw.display_name == "Python cryptography"


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
        framework = FrameworkRepository.get_by_name("Custom Educational")
        algorithm = AlgorithmRepository.get_by_name("DES-CBC")
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


def test_managed_file_crud(sandbox_dir):
    original_path = write_sample_file(sandbox_dir, "crud.txt", b"crud-data")
    with app.app_context():
        managed_file = FileRepository.create(
            original_name="crud.txt",
            original_path=original_path,
            original_hash=HashService.sha256_for_file(original_path),
        )
        assert FileRepository.get_by_id(managed_file.id).original_name == "crud.txt"
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


def test_count_keys_and_get_keys_paginated_empty_db_case():
    with app.app_context():
        for key in KeyRepository.get_all():
            KeyRepository.delete(key.id)
        assert KeyRepository.count_keys() == 0
        assert KeyRepository.get_keys_paginated(1, 10) == []


def test_get_keys_paginated_first_middle_last_pages():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Custom Educational")
        algorithm = AlgorithmRepository.get_by_name("DES-CBC")
        created_names = []
        for index in range(23):
            name = f"page_key_{index:02d}"
            KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=f"value_{index}",
            )
            created_names.append(name)

        assert KeyRepository.count_keys() == 23
        first_page = KeyRepository.get_keys_paginated(1, 10)
        middle_page = KeyRepository.get_keys_paginated(2, 10)
        last_page = KeyRepository.get_keys_paginated(3, 10)

    assert len(first_page) == 10
    assert len(middle_page) == 10
    assert len(last_page) == 3
    ordered_names = [item.name for item in first_page + middle_page + last_page]
    assert ordered_names == list(reversed(created_names))


def test_compatible_key_pagination_for_setup_dropdown():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        hybrid_algorithm = AlgorithmRepository.get_by_name("Hybrid RSA-AES")
        rsa_algorithm = AlgorithmRepository.get_by_name("RSA-2048")

        for index in range(12):
            KeyRepository.create(
                name=f"compat_aes_{index:02d}",
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=f"value_{index}",
            )
        for index in range(7):
            KeyRepository.create(
                name=f"compat_rsa_{index:02d}",
                algorithm_id=rsa_algorithm.id,
                framework_id=framework.id,
                key_type="keypair",
                public_key_value=f"pub_{index}",
                private_key_value=f"priv_{index}",
            )

        assert KeyRepository.count_compatible_active_keys(framework.id, algorithm) == 12
        first_page = KeyRepository.get_compatible_active_keys_paginated(framework.id, algorithm, 1, 5)
        last_page = KeyRepository.get_compatible_active_keys_paginated(framework.id, algorithm, 3, 5)
        hybrid_page = KeyRepository.get_compatible_active_keys_paginated(framework.id, hybrid_algorithm, 1, 10)

    assert len(first_page) == 5
    assert len(last_page) == 2
    assert all(item.algorithm.name == "AES-256-CBC" for item in first_page)
    assert len(hybrid_page) == 7
    assert all(item.algorithm.name == "RSA-2048" for item in hybrid_page)


def test_performance_calculations_include_normalized_metrics():
    metrics = PerformanceMetricCalculator.calculate(50.0, 2.5, 1000, 1200)
    assert metrics.time_per_byte_ms == pytest.approx(0.05)
    assert metrics.time_per_byte_us == pytest.approx(50.0)
    assert metrics.throughput_bytes_per_second == pytest.approx(20000.0)
    assert metrics.throughput_mib_per_second == pytest.approx(20000.0 / (1024 * 1024))


def test_performance_calculations_protect_zero_size_input():
    metrics = PerformanceMetricCalculator.calculate(0.0, 0.0, 0, 0)
    assert metrics.time_per_byte_ms is None
    assert metrics.time_per_byte_us is None
    assert metrics.throughput_bytes_per_second is None
    assert metrics.throughput_mib_per_second is None


def _roundtrip_test(sandbox_dir, algorithm_name, framework_name, file_name, content):
    input_path = write_sample_file(sandbox_dir, file_name, content)
    with app.app_context():
        framework = FrameworkRepository.get_by_name(framework_name)
        algorithm = AlgorithmRepository.get_by_name(algorithm_name)
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name(f"{algorithm_name}_{framework_name}"), algorithm, framework)
        encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)
        refreshed_file = FileRepository.get_by_id(managed_file.id)
        last_encrypt = OperationRepository.get_latest_successful_encrypt_for_file(managed_file.id, algorithm.id, framework.id)
    assert os.path.exists(encrypt_result.output_path)
    assert os.path.exists(decrypt_result.output_path)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert refreshed_file.integrity_verified is True
    assert decrypt_result.performance.execution_time_ms >= 0
    assert decrypt_result.performance.memory_usage_mb >= 0
    assert last_encrypt is not None
    return encrypt_result, decrypt_result, refreshed_file, last_encrypt


def test_aes_openssl_encrypt_decrypt_roundtrip(sandbox_dir):
    _roundtrip_test(sandbox_dir, "AES-256-CBC", "OpenSSL", "openssl_aes.txt", b"OpenSSL AES test content")


def test_aes_custom_encrypt_decrypt_roundtrip(sandbox_dir):
    _roundtrip_test(sandbox_dir, "AES-256-CBC", "Custom Educational", "custom_aes.txt", b"Custom AES roundtrip")


def test_des_openssl_encrypt_decrypt_roundtrip(sandbox_dir):
    _roundtrip_test(sandbox_dir, "DES-CBC", "OpenSSL", "openssl_des.txt", b"OpenSSL DES test content")


def test_des_custom_encrypt_decrypt_roundtrip(sandbox_dir):
    _roundtrip_test(sandbox_dir, "DES-CBC", "Custom Educational", "custom_des.txt", b"Custom DES roundtrip")


def test_rsa_encrypt_decrypt_small_demo_file_works(sandbox_dir):
    _roundtrip_test(sandbox_dir, "RSA-2048", "OpenSSL", "small_rsa.txt", b"small rsa demo")


def test_cryptography_framework_exists_after_seed():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
    assert framework is not None
    assert framework.display_name == "Python cryptography"
    assert (
        framework.description
        == "Real cryptographic framework implemented using the Python cryptography library. Used as an alternative to OpenSSL for performance comparison."
    )


def test_aes_256_gcm_algorithm_exists_after_seed():
    with app.app_context():
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
    assert algorithm is not None
    assert algorithm.type == "symmetric"
    assert algorithm.mode == "GCM"
    assert algorithm.description == "Authenticated symmetric encryption using AES with 256-bit keys in GCM mode."


def test_cryptography_aes_key_generation_stores_base64_32_byte_key():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        key_record = KeyManagementService.generate_key(unique_name("crypto_gcm_key"), algorithm, framework)
        stored = KeyRepository.get_by_id(key_record.id)

    decoded_key = base64.b64decode(stored.key_value.encode("utf-8"))
    assert len(decoded_key) == 32
    assert base64.b64encode(decoded_key).decode("utf-8") == stored.key_value


def test_cryptography_aes_cbc_encrypt_decrypt_hash_matches(sandbox_dir):
    _, _, refreshed_file, encrypt_op = _roundtrip_test(
        sandbox_dir,
        "AES-256-CBC",
        "Cryptography",
        "crypto_aes_cbc.txt",
        b"Cryptography AES CBC content",
    )
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert encrypt_op.auth_tag is not None


def test_cryptography_aes_gcm_encrypt_decrypt_hash_matches(sandbox_dir):
    _, _, refreshed_file, encrypt_op = _roundtrip_test(
        sandbox_dir,
        "AES-256-GCM",
        "Cryptography",
        "crypto_aes_gcm.txt",
        b"Cryptography AES GCM content",
    )
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert encrypt_op.iv_nonce is not None
    assert encrypt_op.auth_tag is not None
    metadata = json.loads(encrypt_op.operation_metadata_json)
    assert metadata["framework"] == "Cryptography"
    assert metadata["algorithm"] == "AES-256-GCM"
    assert metadata["mode"] == "GCM"
    assert metadata["nonce_b64"] == encrypt_op.iv_nonce
    assert metadata["auth_tag_b64"] == encrypt_op.auth_tag


def test_cryptography_aes_gcm_wrong_key_fails_clearly(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "crypto_wrong_key.txt", b"wrong key gcm content")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        managed_file = FileManagementService.register_file(input_path)
        correct_key = KeyManagementService.generate_key(unique_name("crypto_gcm_ok"), algorithm, framework)
        wrong_key = KeyManagementService.generate_key(unique_name("crypto_gcm_bad"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, correct_key)
        with pytest.raises(CryptoServiceError, match="AES-GCM integrity verification failed"):
            CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, wrong_key)


def test_cryptography_aes_gcm_tampered_ciphertext_fails_authentication(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "crypto_tamper.txt", b"tamper detection for aes gcm")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("crypto_gcm_tamper"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)

        with open(encrypted.output_path, "rb") as encrypted_file:
            ciphertext = bytearray(encrypted_file.read())
        ciphertext[0] ^= 0x01
        with open(encrypted.output_path, "wb") as encrypted_file:
            encrypted_file.write(ciphertext)

        refreshed_file = FileRepository.get_by_id(managed_file.id)
        with pytest.raises(CryptoServiceError, match="AES-GCM integrity verification failed"):
            CryptoManagerService.decrypt_file(refreshed_file, algorithm, framework, key_record)


def test_cryptography_operations_create_performance_records(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "crypto_perf.txt", b"cryptography perf test" * 32)
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-GCM")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("crypto_gcm_perf"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypted = CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, key_record)
        encrypt_performance = PerformanceRepository.get_by_operation_id(encrypted.operation.id)
        decrypt_performance = PerformanceRepository.get_by_operation_id(decrypted.operation.id)

    assert encrypt_performance is not None
    assert decrypt_performance is not None
    for performance in (encrypt_performance, decrypt_performance):
        assert performance.execution_time_ms >= 0
        assert performance.memory_usage_mb >= 0
        assert performance.input_size_bytes > 0
        assert performance.output_size_bytes > 0


def test_sha256_hash_correctness(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "hash.txt", b"hash validation")
    expected_hash = hashlib.sha256(b"hash validation").hexdigest()
    assert HashService.sha256_for_file(input_path) == expected_hash


def test_original_hash_equals_decrypted_hash_after_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "hash_roundtrip.txt", b"hash roundtrip validation")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Custom Educational")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("hashkey"), algorithm, framework)
        CryptoManagerService.decrypt_file(
            CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record).managed_file,
            algorithm,
            framework,
            key_record,
        )
        refreshed_file = FileRepository.get_by_id(managed_file.id)
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash


def test_invalid_algorithm_key_combination_is_rejected(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "invalid.txt", b"invalid combo")
    with app.app_context():
        openssl_fw = FrameworkRepository.get_by_name("OpenSSL")
        aes_algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        rsa_algorithm = AlgorithmRepository.get_by_name("RSA-2048")
        managed_file = FileManagementService.register_file(input_path)
        rsa_key = KeyManagementService.generate_key(unique_name("invalidrsa"), rsa_algorithm, openssl_fw)
        with pytest.raises(CryptoServiceError, match="Selected key does not belong to the selected algorithm"):
            CryptoManagerService.encrypt_file(managed_file, aes_algorithm, openssl_fw, rsa_key)


def test_hybrid_rsa_aes_encrypt_decrypt_large_file_and_save_wrapped_key(sandbox_dir):
    large_content = (b"hybrid-large-file-" * 64) + b"tail"
    input_path = write_sample_file(sandbox_dir, "hybrid_large.bin", large_content)
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("Hybrid RSA-AES")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("hybrid"), algorithm, framework)
        encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)
        refreshed_file = FileRepository.get_by_id(managed_file.id)
        encrypt_operation = OperationRepository.get_latest_successful_encrypt_for_file(managed_file.id, algorithm.id, framework.id)
        performance = PerformanceRepository.get_by_operation_id(decrypt_result.operation.id)
    assert len(large_content) > 190
    assert refreshed_file.original_hash == refreshed_file.decrypted_hash
    assert encrypt_operation.encrypted_data_key is not None
    assert encrypt_operation.iv_nonce is not None
    assert encrypt_operation.auth_tag is not None
    assert encrypt_operation.key_wrap_algorithm == "RSA-OAEP-SHA256"
    assert performance is not None


def test_hybrid_rsa_aes_wrong_private_key_fails(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "wrong_key.bin", b"wrong private key test" * 32)
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("Hybrid RSA-AES")
        managed_file = FileManagementService.register_file(input_path)
        correct_key = KeyManagementService.generate_key(unique_name("hybrid_ok"), algorithm, framework)
        wrong_key = KeyManagementService.generate_key(unique_name("hybrid_bad"), algorithm, framework)
        encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, correct_key)
        with pytest.raises(CryptoServiceError, match="private key may be wrong"):
            CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, wrong_key)
