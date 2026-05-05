import json
import math
import os

from Business.cryptography_service import CryptographyCryptoService
from Business.crypto_services.common import (
    HashService,
    MetricCollector,
    NormalizedPerformanceMetrics,
    OperationStateResolver,
    OperationResult,
    PerformanceMetricCalculator,
    RuntimePaths,
)
from Business.crypto_services.constants import (
    ALGORITHM_AES_256_CBC,
    ALGORITHM_AES_256_GCM,
    ALGORITHM_DES_CBC,
    ALGORITHM_DES_LAB,
    ALGORITHM_RSA_2048,
    ALGORITHM_RSA_LAB,
    FRAMEWORK_CRYPTOGRAPHY,
    FRAMEWORK_CUSTOM_ALIASES,
    FRAMEWORK_LAB_EDUCATIONAL,
    FRAMEWORK_OPENSSL,
    OPERATION_DECRYPT,
    OPERATION_ENCRYPT,
    STATUS_DECRYPTED,
    STATUS_ENCRYPTED,
    STATUS_FAILED,
    STATUS_RUNNING,
)
from Business.crypto_services.custom_service import CustomPythonService
from Business.crypto_services.file_management_service import FileManagementService
from Business.crypto_services.key_management_service import KeyManagementService
from Business.crypto_services.openssl_service import OpenSSLService
from Business.errors import CryptoServiceError
from Business.lab_crypto_service import LabCryptoService
from Model.models import utc_now
from Repositories.file_repo import FileRepository
from Repositories.operation_repo import OperationRepository
from Repositories.performance_repo import PerformanceRepository


class CryptoManagerService:
    SYMMETRIC_FRAMEWORK_MAP = {
        ALGORITHM_AES_256_CBC: {FRAMEWORK_OPENSSL, FRAMEWORK_CRYPTOGRAPHY},
        ALGORITHM_DES_CBC: {FRAMEWORK_OPENSSL},
        ALGORITHM_AES_256_GCM: {FRAMEWORK_CRYPTOGRAPHY},
        ALGORITHM_DES_LAB: {FRAMEWORK_LAB_EDUCATIONAL},
    }
    ASYMMETRIC_FRAMEWORK_MAP = {
        ALGORITHM_RSA_2048: {FRAMEWORK_OPENSSL, FRAMEWORK_CRYPTOGRAPHY},
        ALGORITHM_RSA_LAB: {FRAMEWORK_LAB_EDUCATIONAL},
    }

    @classmethod
    def supported_framework_names_for_algorithm(cls, algorithm_name):
        if algorithm_name in cls.SYMMETRIC_FRAMEWORK_MAP:
            return cls.SYMMETRIC_FRAMEWORK_MAP[algorithm_name]
        if algorithm_name in cls.ASYMMETRIC_FRAMEWORK_MAP:
            return cls.ASYMMETRIC_FRAMEWORK_MAP[algorithm_name]
        return set()

    @classmethod
    def is_framework_supported_for_algorithm(cls, framework_name, algorithm_name):
        return framework_name in cls.supported_framework_names_for_algorithm(algorithm_name)

    @classmethod
    def is_key_compatible_with_algorithm(cls, key_record, algorithm):
        if algorithm.type == "hybrid":
            return key_record.key_type in {"keypair", "public", "private"} and getattr(key_record.algorithm, "name", None) == ALGORITHM_RSA_2048
        return key_record.algorithm_id == algorithm.id

    @staticmethod
    def validate_combination(algorithm, key_record, operation_type, framework=None):
        if framework and not CryptoManagerService.is_framework_supported_for_algorithm(framework.name, algorithm.name):
            raise CryptoServiceError(
                f"Unsupported framework/algorithm combination: {framework.name} with {algorithm.name}."
            )

        if key_record.algorithm_id != algorithm.id:
            raise CryptoServiceError("Selected key does not belong to the selected algorithm.")
        if not key_record.is_active:
            raise CryptoServiceError("Selected key is inactive.")
        if framework and key_record.framework_id != framework.id:
            raise CryptoServiceError("Selected key does not belong to the selected framework.")
        if algorithm.type == "symmetric" and key_record.key_type != "symmetric":
            raise CryptoServiceError("Symmetric operations require a symmetric key.")
        if algorithm.type == "asymmetric" and key_record.key_type not in {"keypair", "public", "private"}:
            raise CryptoServiceError("RSA operations require a public/private key pair.")
        if algorithm.name == ALGORITHM_RSA_LAB:
            LabCryptoService.parse_rsa_key_material(key_record)
            return
        if operation_type == OPERATION_DECRYPT and algorithm.type == "asymmetric" and not key_record.private_key_value:
            raise CryptoServiceError("Decryption requires a private key.")

    @staticmethod
    def _create_operation(managed_file, algorithm, framework, key_record, operation_type):
        return OperationRepository.create(
            file_id=managed_file.id,
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_id=key_record.id,
            operation_type=operation_type,
            status=STATUS_RUNNING,
            started_at=utc_now(),
        )

    @staticmethod
    def _save_performance(operation_id, metrics, input_path, output_path):
        calculated = PerformanceMetricCalculator.calculate_from_paths(
            execution_time_ms=metrics.execution_time_ms,
            memory_usage_mb=metrics.memory_usage_mb,
            input_path=input_path,
            output_path=output_path,
        )
        return PerformanceRepository.create(
            operation_id=operation_id,
            execution_time_ms=calculated.execution_time_ms,
            memory_usage_mb=calculated.memory_usage_mb,
            input_size_bytes=calculated.input_size_bytes,
            output_size_bytes=calculated.output_size_bytes,
            time_per_byte_ms=calculated.time_per_byte_ms,
            time_per_byte_us=calculated.time_per_byte_us,
            throughput_bytes_per_second=calculated.throughput_bytes_per_second,
            throughput_mib_per_second=calculated.throughput_mib_per_second,
        )

    @staticmethod
    def _run_symmetric_encrypt(algorithm_name, framework_name, input_path, output_path, key_bytes):
        metadata = {}
        if framework_name == FRAMEWORK_OPENSSL:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                OpenSSLService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_DES_CBC:
                OpenSSLService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == FRAMEWORK_CRYPTOGRAPHY:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                metadata = CryptographyCryptoService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_AES_256_GCM:
                metadata = CryptographyCryptoService.encrypt_aes_256_gcm(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Cryptography algorithm: {algorithm_name}")
        elif framework_name in FRAMEWORK_CUSTOM_ALIASES:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                CustomPythonService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_DES_CBC:
                CustomPythonService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom Educational / Legacy algorithm: {algorithm_name}")
        elif framework_name == FRAMEWORK_LAB_EDUCATIONAL:
            if algorithm_name == ALGORITHM_DES_LAB:
                LabCryptoService.encrypt_des_file(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Lab Educational algorithm: {algorithm_name}")
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")
        return metadata

    @staticmethod
    def _run_symmetric_decrypt(algorithm_name, framework_name, input_path, output_path, key_bytes, source_operation=None):
        metadata = {}
        if framework_name == FRAMEWORK_OPENSSL:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                OpenSSLService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_DES_CBC:
                OpenSSLService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == FRAMEWORK_CRYPTOGRAPHY:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                metadata = CryptographyCryptoService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_AES_256_GCM:
                if not source_operation or not source_operation.iv_nonce or not source_operation.auth_tag:
                    raise CryptoServiceError("AES-GCM decryption requires stored nonce and authentication tag.")
                metadata = CryptographyCryptoService.decrypt_aes_256_gcm(
                    input_path,
                    output_path,
                    key_bytes,
                    source_operation.iv_nonce,
                    source_operation.auth_tag,
                )
            else:
                raise CryptoServiceError(f"Unsupported Cryptography algorithm: {algorithm_name}")
        elif framework_name in FRAMEWORK_CUSTOM_ALIASES:
            if algorithm_name == ALGORITHM_AES_256_CBC:
                CustomPythonService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == ALGORITHM_DES_CBC:
                CustomPythonService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom Educational / Legacy algorithm: {algorithm_name}")
        elif framework_name == FRAMEWORK_LAB_EDUCATIONAL:
            if algorithm_name == ALGORITHM_DES_LAB:
                LabCryptoService.decrypt_des_file(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Lab Educational algorithm: {algorithm_name}")
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")
        return metadata

    @staticmethod
    def _store_operation_metadata(operation_id, metadata, notes=None, status="success", error_message=None):
        payload = dict(metadata or {})
        if "operation_metadata_json" not in payload and payload:
            payload["operation_metadata_json"] = json.dumps(payload, sort_keys=True)
        return OperationRepository.update(
            operation_id,
            status=status,
            notes=notes,
            error_message=error_message,
            encrypted_data_key=payload.get("encrypted_data_key"),
            iv_nonce=payload.get("iv_nonce"),
            auth_tag=payload.get("auth_tag"),
            key_wrap_algorithm=payload.get("key_wrap_algorithm"),
            data_encryption_algorithm=payload.get("data_encryption_algorithm"),
            operation_metadata_json=payload.get("operation_metadata_json"),
        )

    @staticmethod
    def _update_file_after_encryption(managed_file, output_path):
        encrypted_hash = HashService.hashes_for_paths(encrypted_hash=output_path).get("encrypted_hash")
        return FileRepository.update(
            managed_file.id,
            encrypted_path=output_path,
            encrypted_hash=encrypted_hash,
            status=STATUS_ENCRYPTED,
            decrypted_path=None,
            decrypted_hash=None,
            integrity_verified=None,
        )

    @staticmethod
    def _update_file_after_decryption(managed_file, output_path):
        decrypted_hash = HashService.hashes_for_paths(decrypted_hash=output_path).get("decrypted_hash")
        integrity_ok = HashService.is_integrity_verified(managed_file.original_hash, decrypted_hash)
        notes = "Hash verification passed." if integrity_ok else "Hash verification failed."
        status = STATUS_DECRYPTED if integrity_ok else STATUS_FAILED
        updated_file = FileRepository.update(
            managed_file.id,
            decrypted_path=output_path,
            decrypted_hash=decrypted_hash,
            integrity_verified=integrity_ok,
            status=status,
        )
        return updated_file, notes, integrity_ok

    @staticmethod
    def _mark_operation_failed(managed_file, operation_id, exc):
        FileRepository.update(managed_file.id, status=STATUS_FAILED)
        OperationRepository.update(operation_id, status=STATUS_FAILED, error_message=str(exc))

    @staticmethod
    def encrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record, OPERATION_ENCRYPT, framework)
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, OPERATION_ENCRYPT)
        output_path = RuntimePaths.build_encrypted_output_path(managed_file, algorithm)
        try:
            with MetricCollector() as metrics:
                metadata = {}
                if algorithm.type == "symmetric":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    metadata = CryptoManagerService._run_symmetric_encrypt(
                        algorithm.name, framework.name, managed_file.original_path, output_path, key_bytes
                    )
                elif algorithm.name == ALGORITHM_RSA_2048:
                    public_path, _ = KeyManagementService.key_paths(key_record)
                    if framework.name == FRAMEWORK_OPENSSL:
                        if not public_path:
                            raise CryptoServiceError("RSA encryption requires a stored public key path.")
                        OpenSSLService.encrypt_rsa_2048(managed_file.original_path, output_path, public_path)
                    elif framework.name == FRAMEWORK_CRYPTOGRAPHY:
                        if not key_record.public_key_value:
                            raise CryptoServiceError("RSA encryption requires a stored public key.")
                        CryptographyCryptoService.encrypt_rsa_2048(
                            managed_file.original_path, output_path, key_record.public_key_value
                        )
                    else:
                        raise CryptoServiceError("RSA encryption is not supported by the legacy custom framework.")
                    metadata = {
                        "key_wrap_algorithm": "RSA-OAEP-SHA256",
                        "data_encryption_algorithm": ALGORITHM_RSA_2048,
                    }
                elif algorithm.name == ALGORITHM_RSA_LAB:
                    n, e, _ = LabCryptoService.parse_rsa_key_material(key_record)
                    LabCryptoService.rsa_encrypt_file(managed_file.original_path, output_path, e, n)
                    metadata = {
                        "data_encryption_algorithm": ALGORITHM_RSA_LAB,
                        "operation_metadata_json": json.dumps(
                            {"framework": FRAMEWORK_LAB_EDUCATIONAL, "algorithm": ALGORITHM_RSA_LAB, "mode": "Textbook RSA"},
                            sort_keys=True,
                        ),
                    }
                else:
                    raise CryptoServiceError(f"Unsupported algorithm: {algorithm.name}")

            CryptoManagerService._update_file_after_encryption(managed_file, output_path)
            CryptoManagerService._store_operation_metadata(
                operation.id, metadata, notes=f"{algorithm.name} encryption completed."
            )
            performance = CryptoManagerService._save_performance(operation.id, metrics, managed_file.original_path, output_path)
            return OperationResult(
                managed_file=FileRepository.get_by_id(managed_file.id),
                operation=OperationRepository.get_by_id(operation.id),
                performance=PerformanceRepository.get_by_id(performance.id),
                output_path=output_path,
                message="Encryption completed successfully.",
            )
        except Exception as exc:
            CryptoManagerService._mark_operation_failed(managed_file, operation.id, exc)
            raise

    @staticmethod
    def decrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record, OPERATION_DECRYPT, framework)
        if not managed_file.encrypted_path or not os.path.exists(managed_file.encrypted_path):
            raise CryptoServiceError("No encrypted file is registered for the selected record.")
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, OPERATION_DECRYPT)
        output_path = RuntimePaths.build_decrypted_output_path(managed_file)
        try:
            source_operation = OperationRepository.get_latest_successful_encrypt_for_file(
                managed_file.id, algorithm_id=algorithm.id, framework_id=framework.id
            )
            with MetricCollector() as metrics:
                metadata = {}
                if algorithm.type == "symmetric":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    metadata = CryptoManagerService._run_symmetric_decrypt(
                        algorithm.name,
                        framework.name,
                        managed_file.encrypted_path,
                        output_path,
                        key_bytes,
                        source_operation=source_operation,
                    )
                elif algorithm.name == ALGORITHM_RSA_2048:
                    _, private_path = KeyManagementService.key_paths(key_record)
                    if framework.name == FRAMEWORK_OPENSSL:
                        if not private_path:
                            raise CryptoServiceError("RSA decryption requires a stored private key path.")
                        OpenSSLService.decrypt_rsa_2048(managed_file.encrypted_path, output_path, private_path)
                    elif framework.name == FRAMEWORK_CRYPTOGRAPHY:
                        if not key_record.private_key_value:
                            raise CryptoServiceError("RSA decryption requires a stored private key.")
                        CryptographyCryptoService.decrypt_rsa_2048(
                            managed_file.encrypted_path, output_path, key_record.private_key_value
                        )
                    else:
                        raise CryptoServiceError("RSA decryption is not supported by the legacy custom framework.")
                elif algorithm.name == ALGORITHM_RSA_LAB:
                    n, _, d = LabCryptoService.parse_rsa_key_material(key_record)
                    LabCryptoService.rsa_decrypt_file(managed_file.encrypted_path, output_path, d, n)
                    metadata = {
                        "data_encryption_algorithm": ALGORITHM_RSA_LAB,
                        "operation_metadata_json": json.dumps(
                            {"framework": FRAMEWORK_LAB_EDUCATIONAL, "algorithm": ALGORITHM_RSA_LAB, "mode": "Textbook RSA"},
                            sort_keys=True,
                        ),
                    }
                else:
                    raise CryptoServiceError(f"Unsupported algorithm: {algorithm.name}")

            _, notes, integrity_ok = CryptoManagerService._update_file_after_decryption(managed_file, output_path)
            CryptoManagerService._store_operation_metadata(
                operation.id,
                metadata,
                notes=notes,
                status=OperationStateResolver.completion_status(integrity_ok),
                error_message=None if integrity_ok else "Decrypted hash does not match original hash.",
            )
            performance = CryptoManagerService._save_performance(operation.id, metrics, managed_file.encrypted_path, output_path)
            return OperationResult(
                managed_file=FileRepository.get_by_id(managed_file.id),
                operation=OperationRepository.get_by_id(operation.id),
                performance=PerformanceRepository.get_by_id(performance.id),
                output_path=output_path,
                message=notes,
            )
        except Exception as exc:
            CryptoManagerService._mark_operation_failed(managed_file, operation.id, exc)
            raise

    @staticmethod
    def format_performance_summary(performance):
        def fmt(value, digits=4):
            if value is None:
                return "N/A"
            if isinstance(value, (int, float)) and not math.isfinite(value):
                return "N/A"
            return f"{value:.{digits}f}"

        return (
            f"Time: {performance.execution_time_ms:.2f} ms\n"
            f"Memory: {performance.memory_usage_mb:.4f} MB\n"
            f"Input size: {performance.input_size_bytes} bytes\n"
            f"Output size: {performance.output_size_bytes} bytes\n"
            f"Time per byte: {fmt(performance.time_per_byte_us)} us\n"
            f"Throughput: {fmt(performance.throughput_mib_per_second)} MiB/s"
        )


__all__ = [
    "CryptoManagerService",
    "CustomPythonService",
    "FileManagementService",
    "HashService",
    "KeyManagementService",
    "MetricCollector",
    "NormalizedPerformanceMetrics",
    "OpenSSLService",
    "OperationResult",
    "PerformanceMetricCalculator",
    "RuntimePaths",
]
