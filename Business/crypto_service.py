import json
import math
import os
from pathlib import Path

from Business.cryptography_service import CryptographyCryptoService
from Business.crypto_services.common import (
    HashService,
    MetricCollector,
    NormalizedPerformanceMetrics,
    OperationResult,
    PerformanceMetricCalculator,
    RuntimePaths,
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
        "AES-256-CBC": {"OpenSSL", "Cryptography", "Custom Educational"},
        "AES-256-GCM": {"Cryptography"},
        "DES-CBC": {"OpenSSL", "Custom Educational"},
        "DES-LAB": {"Lab Educational"},
    }
    ASYMMETRIC_FRAMEWORK_MAP = {
        "RSA-2048": {"OpenSSL", "Cryptography"},
        "Hybrid RSA-AES": {"Cryptography"},
        "RSA-LAB": {"Lab Educational"},
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
            return key_record.key_type in {"keypair", "public", "private"} and getattr(key_record.algorithm, "name", None) == "RSA-2048"
        return key_record.algorithm_id == algorithm.id

    @staticmethod
    def validate_combination(algorithm, key_record, operation_type, framework=None):
        if framework and not CryptoManagerService.is_framework_supported_for_algorithm(framework.name, algorithm.name):
            raise CryptoServiceError(
                f"Unsupported framework/algorithm combination: {framework.name} with {algorithm.name}."
            )
        if algorithm.type == "hybrid":
            if key_record.key_type not in {"keypair", "public", "private"}:
                raise CryptoServiceError("Hybrid RSA-AES operations require an RSA key pair.")
            if not key_record.is_active:
                raise CryptoServiceError("Selected key is inactive.")
            if framework and key_record.framework_id != framework.id:
                raise CryptoServiceError("Selected RSA key does not belong to the selected framework.")
            return

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
        if algorithm.name == "RSA-LAB":
            LabCryptoService.parse_rsa_key_material(key_record)
            return
        if operation_type == "decrypt" and algorithm.type in {"asymmetric", "hybrid"} and not key_record.private_key_value:
            raise CryptoServiceError("Decryption requires a private key.")

    @staticmethod
    def _create_operation(managed_file, algorithm, framework, key_record, operation_type):
        return OperationRepository.create(
            file_id=managed_file.id,
            algorithm_id=algorithm.id,
            framework_id=framework.id,
            key_id=key_record.id,
            operation_type=operation_type,
            status="running",
            started_at=utc_now(),
        )

    @staticmethod
    def _save_performance(operation_id, metrics, input_path, output_path):
        calculated = PerformanceMetricCalculator.calculate(
            execution_time_ms=metrics.execution_time_ms,
            memory_usage_mb=metrics.memory_usage_mb,
            input_size_bytes=os.path.getsize(input_path) if os.path.exists(input_path) else 0,
            output_size_bytes=os.path.getsize(output_path) if os.path.exists(output_path) else 0,
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
        if framework_name == "OpenSSL":
            if algorithm_name == "AES-256-CBC":
                OpenSSLService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                OpenSSLService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == "Cryptography":
            if algorithm_name == "AES-256-CBC":
                metadata = CryptographyCryptoService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "AES-256-GCM":
                metadata = CryptographyCryptoService.encrypt_aes_256_gcm(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Cryptography algorithm: {algorithm_name}")
        elif framework_name == "Custom Educational":
            if algorithm_name == "AES-256-CBC":
                CustomPythonService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                CustomPythonService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom Educational algorithm: {algorithm_name}")
        elif framework_name == "Lab Educational":
            if algorithm_name == "DES-LAB":
                LabCryptoService.encrypt_des_file(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Lab Educational algorithm: {algorithm_name}")
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")
        return metadata

    @staticmethod
    def _run_symmetric_decrypt(algorithm_name, framework_name, input_path, output_path, key_bytes, source_operation=None):
        metadata = {}
        if framework_name == "OpenSSL":
            if algorithm_name == "AES-256-CBC":
                OpenSSLService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                OpenSSLService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == "Cryptography":
            if algorithm_name == "AES-256-CBC":
                metadata = CryptographyCryptoService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "AES-256-GCM":
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
        elif framework_name == "Custom Educational":
            if algorithm_name == "AES-256-CBC":
                CustomPythonService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                CustomPythonService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom Educational algorithm: {algorithm_name}")
        elif framework_name == "Lab Educational":
            if algorithm_name == "DES-LAB":
                LabCryptoService.decrypt_des_file(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Lab Educational algorithm: {algorithm_name}")
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")
        return metadata

    @staticmethod
    def _build_output_path(managed_file, algorithm, suffix):
        safe_algorithm = algorithm.name.lower().replace("-", "_").replace(" ", "_")
        output_name = f"{Path(managed_file.original_name).name}.{safe_algorithm}{suffix}"
        target_dir = RuntimePaths.encrypted_dir if suffix == ".enc" else RuntimePaths.decrypted_dir
        return os.path.join(target_dir, output_name)

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
    def encrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record, "encrypt", framework)
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, "encrypt")
        output_path = CryptoManagerService._build_output_path(managed_file, algorithm, ".enc")
        try:
            with MetricCollector() as metrics:
                metadata = {}
                if algorithm.type == "symmetric":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    metadata = CryptoManagerService._run_symmetric_encrypt(
                        algorithm.name, framework.name, managed_file.original_path, output_path, key_bytes
                    )
                elif algorithm.name == "RSA-2048":
                    public_path, _ = KeyManagementService.key_paths(key_record)
                    if framework.name == "OpenSSL":
                        if not public_path:
                            raise CryptoServiceError("RSA encryption requires a stored public key path.")
                        OpenSSLService.encrypt_rsa_2048(managed_file.original_path, output_path, public_path)
                    elif framework.name == "Cryptography":
                        if not key_record.public_key_value:
                            raise CryptoServiceError("RSA encryption requires a stored public key.")
                        CryptographyCryptoService.encrypt_rsa_2048(
                            managed_file.original_path, output_path, key_record.public_key_value
                        )
                    else:
                        raise CryptoServiceError("RSA encryption is not supported by the legacy custom framework.")
                    metadata = {
                        "key_wrap_algorithm": "RSA-OAEP-SHA256",
                        "data_encryption_algorithm": "RSA-2048",
                    }
                elif algorithm.name == "RSA-LAB":
                    n, e, _ = LabCryptoService.parse_rsa_key_material(key_record)
                    LabCryptoService.rsa_encrypt_file(managed_file.original_path, output_path, e, n)
                    metadata = {
                        "data_encryption_algorithm": "RSA-LAB",
                        "operation_metadata_json": json.dumps(
                            {"framework": "Lab Educational", "algorithm": "RSA-LAB", "mode": "Textbook RSA"},
                            sort_keys=True,
                        ),
                    }
                elif algorithm.name == "Hybrid RSA-AES":
                    if framework.name != "Cryptography":
                        raise CryptoServiceError("Hybrid RSA-AES is currently supported with the Cryptography framework.")
                    if not key_record.public_key_value:
                        raise CryptoServiceError("Hybrid encryption requires a stored RSA public key.")
                    metadata = CryptographyCryptoService.encrypt_hybrid_rsa_aes(
                        managed_file.original_path, output_path, key_record.public_key_value
                    )
                else:
                    raise CryptoServiceError(f"Unsupported algorithm: {algorithm.name}")

            encrypted_hash = HashService.sha256_for_file(output_path)
            FileRepository.update(
                managed_file.id,
                encrypted_path=output_path,
                encrypted_hash=encrypted_hash,
                status="encrypted",
                decrypted_path=None,
                decrypted_hash=None,
                integrity_verified=None,
            )
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
            FileRepository.update(managed_file.id, status="failed")
            OperationRepository.update(operation.id, status="failed", error_message=str(exc))
            raise

    @staticmethod
    def decrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record, "decrypt", framework)
        if not managed_file.encrypted_path or not os.path.exists(managed_file.encrypted_path):
            raise CryptoServiceError("No encrypted file is registered for the selected record.")
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, "decrypt")
        output_path = os.path.join(RuntimePaths.decrypted_dir, f"decrypted_{Path(managed_file.original_name).name}")
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
                elif algorithm.name == "RSA-2048":
                    _, private_path = KeyManagementService.key_paths(key_record)
                    if framework.name == "OpenSSL":
                        if not private_path:
                            raise CryptoServiceError("RSA decryption requires a stored private key path.")
                        OpenSSLService.decrypt_rsa_2048(managed_file.encrypted_path, output_path, private_path)
                    elif framework.name == "Cryptography":
                        if not key_record.private_key_value:
                            raise CryptoServiceError("RSA decryption requires a stored private key.")
                        CryptographyCryptoService.decrypt_rsa_2048(
                            managed_file.encrypted_path, output_path, key_record.private_key_value
                        )
                    else:
                        raise CryptoServiceError("RSA decryption is not supported by the legacy custom framework.")
                elif algorithm.name == "RSA-LAB":
                    n, _, d = LabCryptoService.parse_rsa_key_material(key_record)
                    LabCryptoService.rsa_decrypt_file(managed_file.encrypted_path, output_path, d, n)
                    metadata = {
                        "data_encryption_algorithm": "RSA-LAB",
                        "operation_metadata_json": json.dumps(
                            {"framework": "Lab Educational", "algorithm": "RSA-LAB", "mode": "Textbook RSA"},
                            sort_keys=True,
                        ),
                    }
                elif algorithm.name == "Hybrid RSA-AES":
                    if framework.name != "Cryptography":
                        raise CryptoServiceError("Hybrid RSA-AES is currently supported with the Cryptography framework.")
                    if not source_operation:
                        raise CryptoServiceError("Hybrid decryption requires stored encryption metadata.")
                    metadata = CryptographyCryptoService.decrypt_hybrid_rsa_aes(
                        managed_file.encrypted_path,
                        output_path,
                        key_record.private_key_value,
                        source_operation.encrypted_data_key,
                        source_operation.iv_nonce,
                        source_operation.auth_tag,
                    )
                    metadata["encrypted_data_key"] = source_operation.encrypted_data_key
                    metadata["key_wrap_algorithm"] = source_operation.key_wrap_algorithm
                else:
                    raise CryptoServiceError(f"Unsupported algorithm: {algorithm.name}")

            decrypted_hash = HashService.sha256_for_file(output_path)
            integrity_ok = bool(managed_file.original_hash and managed_file.original_hash == decrypted_hash)
            notes = "Hash verification passed." if integrity_ok else "Hash verification failed."
            FileRepository.update(
                managed_file.id,
                decrypted_path=output_path,
                decrypted_hash=decrypted_hash,
                integrity_verified=integrity_ok,
                status="decrypted" if integrity_ok else "failed",
            )
            CryptoManagerService._store_operation_metadata(
                operation.id,
                metadata,
                notes=notes,
                status="success" if integrity_ok else "failed",
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
            FileRepository.update(managed_file.id, status="failed")
            OperationRepository.update(operation.id, status="failed", error_message=str(exc))
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
