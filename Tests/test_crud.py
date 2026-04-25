import os
import shutil
import uuid

import pytest
from sqlalchemy import inspect

from Business.crypto_service import (
    CryptoManagerService,
    CryptoServiceError,
    FileManagementService,
    HashService,
    KeyManagementService,
    OpenSSLService,
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


@pytest.fixture(autouse=True)
def clean_database():
    ensure_runtime_directories()
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_defaults()
        yield
        db.session.remove()


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


def get_default_framework(name):
    with app.app_context():
        return FrameworkRepository.get_by_name(name)


def get_default_algorithm(name):
    with app.app_context():
        return AlgorithmRepository.get_by_name(name)


def test_database_creation_works():
    init_db(seed=True)
    with app.app_context():
        inspector = inspect(db.engine)
        table_names = set(inspector.get_table_names())
    assert {
        "frameworks",
        "algorithms",
        "keys",
        "managed_files",
        "crypto_operations",
        "performances",
    }.issubset(table_names)


def test_framework_crud():
    with app.app_context():
        framework = FrameworkRepository.create(unique_name("Framework"), "Python library", "1.0")
        fetched = FrameworkRepository.get_by_id(framework.id)
        assert fetched.name == framework.name

        updated = FrameworkRepository.update(framework.id, version="1.1")
        assert updated.version == "1.1"
        assert any(item.id == framework.id for item in FrameworkRepository.get_all())

        assert FrameworkRepository.delete(framework.id) is True
        assert FrameworkRepository.get_by_id(framework.id) is None


def test_algorithm_crud():
    with app.app_context():
        algorithm = AlgorithmRepository.create(
            unique_name("Algo"),
            "symmetric",
            128,
            mode="CBC",
            description="test algorithm",
        )
        assert AlgorithmRepository.get_by_id(algorithm.id).name == algorithm.name

        updated = AlgorithmRepository.update(algorithm.id, description="updated")
        assert updated.description == "updated"
        assert any(item.id == algorithm.id for item in AlgorithmRepository.get_all())

        assert AlgorithmRepository.delete(algorithm.id) is True
        assert AlgorithmRepository.get_by_id(algorithm.id) is None


def test_key_crud():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        key_record = KeyRepository.create(
            name=unique_name("key"),
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_type="symmetric",
            key_value="ZmFrZV9rZXk=",
        )
        assert KeyRepository.get_by_id(key_record.id).name == key_record.name

        updated = KeyRepository.update(key_record.id, is_active=False)
        assert updated.is_active is False
        assert any(item.id == key_record.id for item in KeyRepository.get_all())

        assert KeyRepository.delete(key_record.id) is True
        assert KeyRepository.get_by_id(key_record.id) is None


def test_managed_file_crud(sandbox_dir):
    original_path = write_sample_file(sandbox_dir, "crud.txt", b"crud-data")
    with app.app_context():
        managed_file = FileRepository.create(
            original_name="crud.txt",
            original_path=original_path,
            original_hash=HashService.sha256_for_file(original_path),
        )
        assert FileRepository.get_by_id(managed_file.id).original_name == "crud.txt"

        updated = FileRepository.update(managed_file.id, status="encrypted", encrypted_path="enc.bin")
        assert updated.status == "encrypted"
        assert any(item.id == managed_file.id for item in FileRepository.get_all())

        assert FileRepository.delete(managed_file.id) is True
        assert FileRepository.get_by_id(managed_file.id) is None


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

        updated_operation = OperationRepository.update(operation.id, status="success", notes="ok")
        assert updated_operation.status == "success"

        performance = PerformanceRepository.create(operation.id, 12.5, 1.2, 100, 120)
        assert PerformanceRepository.get_by_id(performance.id).operation_id == operation.id
        assert PerformanceRepository.update(performance.id, execution_time_ms=14.0).execution_time_ms == 14.0

        assert PerformanceRepository.delete(performance.id) is True
        assert OperationRepository.delete(operation.id) is True


def test_aes_openssl_encrypt_decrypt_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "openssl_aes.txt", b"OpenSSL AES test content")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("aesopenssl"), algorithm, framework)

        encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)

        refreshed_file = FileRepository.get_by_id(managed_file.id)
        assert os.path.exists(encrypt_result.output_path)
        assert os.path.exists(decrypt_result.output_path)
        assert refreshed_file.original_hash == refreshed_file.decrypted_hash
        assert refreshed_file.integrity_verified is True
        assert decrypt_result.performance.execution_time_ms >= 0
        assert decrypt_result.performance.memory_usage_mb >= 0


def test_aes_cryptography_encrypt_decrypt_roundtrip(sandbox_dir):
    pytest.importorskip("cryptography")
    input_path = write_sample_file(sandbox_dir, "crypto_aes.txt", b"Cryptography AES roundtrip")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("Cryptography")
        algorithm = AlgorithmRepository.get_by_name("AES-256-CBC")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("aescrypto"), algorithm, framework)

        encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)

        refreshed_file = FileRepository.get_by_id(managed_file.id)
        assert os.path.exists(encrypt_result.output_path)
        assert os.path.exists(decrypt_result.output_path)
        assert refreshed_file.original_hash == refreshed_file.decrypted_hash
        assert refreshed_file.integrity_verified is True


def test_original_hash_equals_decrypted_hash_after_roundtrip(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "hash.txt", b"hash validation")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
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


def test_rsa_key_generation_works():
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("RSA-2048")
        key_record = KeyManagementService.generate_key(unique_name("rsa"), algorithm, framework)
        public_path, private_path = key_record.key_path.split("|", 1)

    assert os.path.exists(public_path)
    assert os.path.exists(private_path)
    assert "BEGIN PUBLIC KEY" in key_record.public_key_value
    assert "BEGIN RSA PRIVATE KEY" in key_record.private_key_value or "BEGIN PRIVATE KEY" in key_record.private_key_value


def test_rsa_encrypt_decrypt_small_demo_file_works(sandbox_dir):
    input_path = write_sample_file(sandbox_dir, "small_rsa.txt", b"small rsa demo")
    with app.app_context():
        framework = FrameworkRepository.get_by_name("OpenSSL")
        algorithm = AlgorithmRepository.get_by_name("RSA-2048")
        managed_file = FileManagementService.register_file(input_path)
        key_record = KeyManagementService.generate_key(unique_name("rsaenc"), algorithm, framework)

        encrypt_result = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
        decrypt_result = CryptoManagerService.decrypt_file(encrypt_result.managed_file, algorithm, framework, key_record)
        refreshed_file = FileRepository.get_by_id(managed_file.id)

    assert os.path.exists(encrypt_result.output_path)
    assert os.path.exists(decrypt_result.output_path)
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
