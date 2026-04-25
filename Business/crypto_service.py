import base64
import binascii
import hashlib
import os
import secrets
import shutil
import subprocess
import time
import tracemalloc
from typing import Any
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - optional fallback
    psutil = None

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
except ImportError:  # pragma: no cover - handled at runtime
    hashes = serialization = padding = rsa = Cipher = algorithms = modes = PKCS7 = None

from Model.models import BASE_DIR, utc_now
from Repositories.file_repo import FileRepository
from Repositories.key_repo import KeyRepository
from Repositories.operation_repo import OperationRepository
from Repositories.performance_repo import PerformanceRepository


class CryptoServiceError(Exception):
    pass


@dataclass
class OperationResult:
    managed_file: Any
    operation: Any
    performance: Any
    output_path: str
    message: str


class HashService:
    @staticmethod
    def sha256_for_file(file_path):
        digest = hashlib.sha256()
        with open(file_path, "rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()


class RuntimePaths:
    original_dir = os.path.join(BASE_DIR, "data", "original")
    encrypted_dir = os.path.join(BASE_DIR, "data", "encrypted")
    decrypted_dir = os.path.join(BASE_DIR, "data", "decrypted")
    keys_dir = os.path.join(BASE_DIR, "data", "keys")


class MetricCollector:
    def __enter__(self):
        self.started_at = utc_now()
        self.start_time = time.perf_counter()
        tracemalloc.start()
        self.process = psutil.Process(os.getpid()) if psutil else None
        self.start_rss = self.process.memory_info().rss if self.process else 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_rss = self.process.memory_info().rss if self.process else 0
        rss_delta = max(end_rss - self.start_rss, 0)
        self.finished_at = utc_now()
        self.execution_time_ms = (time.perf_counter() - self.start_time) * 1000
        self.memory_usage_mb = max(peak, current, rss_delta) / (1024 * 1024)


class OpenSSLService:
    MAX_RSA_INPUT_BYTES = 190

    @staticmethod
    def resolve_openssl_path():
        candidates = [
            os.environ.get("OPENSSL_BIN"),
            shutil.which("openssl"),
            r"C:\Program Files\Git\mingw64\bin\openssl.exe",
            r"C:\Program Files\Git\usr\bin\openssl.exe",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate
        raise CryptoServiceError(
            "OpenSSL executable not found. Set OPENSSL_BIN or install OpenSSL."
        )

    @classmethod
    def run_command(cls, arguments):
        command = [cls.resolve_openssl_path(), *arguments]
        try:
            return subprocess.run(command, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as exc:
            error_message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise CryptoServiceError(error_message) from exc

    @staticmethod
    def generate_aes_key():
        return secrets.token_bytes(32)

    @classmethod
    def generate_rsa_key_pair(cls, private_path, public_path):
        cls.run_command(["genpkey", "-algorithm", "RSA", "-out", private_path, "-pkeyopt", "rsa_keygen_bits:2048"])
        cls.run_command(["rsa", "-pubout", "-in", private_path, "-out", public_path])
        with open(private_path, "r", encoding="utf-8") as private_file:
            private_pem = private_file.read()
        with open(public_path, "r", encoding="utf-8") as public_file:
            public_pem = public_file.read()
        return public_pem, private_pem

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        key_hex = binascii.hexlify(key_bytes).decode("utf-8")
        iv_bytes = secrets.token_bytes(16)
        iv_hex = binascii.hexlify(iv_bytes).decode("utf-8")
        cls.run_command(
            [
                "enc",
                "-aes-256-cbc",
                "-in",
                input_path,
                "-out",
                output_path,
                "-K",
                key_hex,
                "-iv",
                iv_hex,
            ]
        )
        with open(output_path, "rb") as encrypted_file:
            encrypted_payload = encrypted_file.read()
        with open(output_path, "wb") as encrypted_file:
            encrypted_file.write(iv_bytes + encrypted_payload)

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        with open(input_path, "rb") as encrypted_file:
            iv_bytes = encrypted_file.read(16)
            encrypted_payload = encrypted_file.read()
        temp_payload_path = f"{output_path}.openssl.tmp"
        with open(temp_payload_path, "wb") as temp_payload:
            temp_payload.write(encrypted_payload)
        try:
            key_hex = binascii.hexlify(key_bytes).decode("utf-8")
            iv_hex = binascii.hexlify(iv_bytes).decode("utf-8")
            cls.run_command(
                [
                    "enc",
                    "-d",
                    "-aes-256-cbc",
                    "-in",
                    temp_payload_path,
                    "-out",
                    output_path,
                    "-K",
                    key_hex,
                    "-iv",
                    iv_hex,
                ]
            )
        finally:
            if os.path.exists(temp_payload_path):
                os.remove(temp_payload_path)

    @classmethod
    def encrypt_rsa_2048(cls, input_path, output_path, public_key_path):
        input_size = os.path.getsize(input_path)
        if input_size > cls.MAX_RSA_INPUT_BYTES:
            raise CryptoServiceError(
                "RSA is only used for small demo files or key encryption. Use AES for normal file encryption."
            )
        cls.run_command(
            [
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                public_key_path,
                "-in",
                input_path,
                "-out",
                output_path,
            ]
        )

    @classmethod
    def decrypt_rsa_2048(cls, input_path, output_path, private_key_path):
        cls.run_command(
            [
                "pkeyutl",
                "-decrypt",
                "-inkey",
                private_key_path,
                "-in",
                input_path,
                "-out",
                output_path,
            ]
        )


class CryptographyService:
    @staticmethod
    def _require_dependency():
        if Cipher is None:
            raise CryptoServiceError(
                "The 'cryptography' package is not installed. Install dependencies first."
            )

    @classmethod
    def generate_aes_key(cls):
        cls._require_dependency()
        return secrets.token_bytes(32)

    @classmethod
    def generate_rsa_key_pair(cls):
        cls._require_dependency()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return public_pem, private_pem

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._require_dependency()
        iv_bytes = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
        encryptor = cipher.encryptor()
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        with open(output_path, "wb") as target_file:
            target_file.write(iv_bytes + ciphertext)

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._require_dependency()
        with open(input_path, "rb") as source_file:
            iv_bytes = source_file.read(16)
            ciphertext = source_file.read()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv_bytes))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)


class KeyManagementService:
    @staticmethod
    def _write_key_file(file_name, content):
        key_path = os.path.join(RuntimePaths.keys_dir, file_name)
        with open(key_path, "w", encoding="utf-8") as key_file:
            key_file.write(content)
        return key_path

    @staticmethod
    def generate_key(name, algorithm, framework):
        algorithm_name = algorithm.name.upper()
        framework_name = framework.name.lower()

        if algorithm_name.startswith("AES"):
            if framework_name == "openssl":
                key_bytes = OpenSSLService.generate_aes_key()
            else:
                key_bytes = CryptographyService.generate_aes_key()
            encoded_key = base64.b64encode(key_bytes).decode("utf-8")
            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=encoded_key,
            )

        if algorithm_name.startswith("RSA"):
            private_path = os.path.join(RuntimePaths.keys_dir, f"{name}_private.pem")
            public_path = os.path.join(RuntimePaths.keys_dir, f"{name}_public.pem")
            if framework_name == "openssl":
                public_pem, private_pem = OpenSSLService.generate_rsa_key_pair(private_path, public_path)
            else:
                public_pem, private_pem = CryptographyService.generate_rsa_key_pair()
                private_path = KeyManagementService._write_key_file(f"{name}_private.pem", private_pem)
                public_path = KeyManagementService._write_key_file(f"{name}_public.pem", public_pem)

            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="keypair",
                key_path=f"{public_path}|{private_path}",
                public_key_value=public_pem,
                private_key_value=private_pem,
            )

        raise CryptoServiceError(f"Unsupported algorithm for key generation: {algorithm.name}")

    @staticmethod
    def decode_symmetric_key(key_record):
        if not key_record.key_value:
            raise CryptoServiceError("Selected symmetric key has no stored value.")
        return base64.b64decode(key_record.key_value.encode("utf-8"))

    @staticmethod
    def key_paths(key_record):
        public_path = private_path = None
        if key_record.key_path and "|" in key_record.key_path:
            public_path, private_path = key_record.key_path.split("|", 1)
        return public_path, private_path


class FileManagementService:
    @staticmethod
    def register_file(file_path):
        original_name = os.path.basename(file_path)
        target_path = os.path.join(RuntimePaths.original_dir, original_name)
        if os.path.abspath(file_path) != os.path.abspath(target_path):
            shutil.copy2(file_path, target_path)
        original_hash = HashService.sha256_for_file(target_path)
        existing = next(
            (item for item in FileRepository.get_all() if os.path.abspath(item.original_path) == os.path.abspath(target_path)),
            None,
        )
        if existing:
            return FileRepository.update(
                existing.id,
                original_name=original_name,
                original_path=target_path,
                original_hash=original_hash,
                status="plain",
            )
        return FileRepository.create(
            original_name=original_name,
            original_path=target_path,
            original_hash=original_hash,
            status="plain",
        )


class CryptoManagerService:
    @staticmethod
    def validate_combination(algorithm, key_record):
        if key_record.algorithm_id != algorithm.id:
            raise CryptoServiceError("Selected key does not belong to the selected algorithm.")
        if not key_record.is_active:
            raise CryptoServiceError("Selected key is inactive.")
        if algorithm.type == "symmetric" and key_record.key_type != "symmetric":
            raise CryptoServiceError("AES operations require a symmetric key.")
        if algorithm.type == "asymmetric" and key_record.key_type not in {"keypair", "public", "private"}:
            raise CryptoServiceError("RSA operations require a public/private key pair.")

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
        return PerformanceRepository.create(
            operation_id=operation_id,
            execution_time_ms=metrics.execution_time_ms,
            memory_usage_mb=metrics.memory_usage_mb,
            input_size_bytes=os.path.getsize(input_path) if os.path.exists(input_path) else 0,
            output_size_bytes=os.path.getsize(output_path) if os.path.exists(output_path) else 0,
        )

    @staticmethod
    def _run_aes_encrypt(framework_name, input_path, output_path, key_bytes):
        if framework_name == "OpenSSL":
            OpenSSLService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
        elif framework_name == "Cryptography":
            CryptographyService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")

    @staticmethod
    def _run_aes_decrypt(framework_name, input_path, output_path, key_bytes):
        if framework_name == "OpenSSL":
            OpenSSLService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
        elif framework_name == "Cryptography":
            CryptographyService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")

    @staticmethod
    def encrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record)
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, "encrypt")
        output_name = f"{Path(managed_file.original_name).name}.{algorithm.name.lower().replace('-', '_')}.enc"
        output_path = os.path.join(RuntimePaths.encrypted_dir, output_name)
        try:
            with MetricCollector() as metrics:
                if algorithm.name == "AES-256-CBC":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    CryptoManagerService._run_aes_encrypt(
                        framework.name, managed_file.original_path, output_path, key_bytes
                    )
                elif algorithm.name == "RSA-2048":
                    public_path, _ = KeyManagementService.key_paths(key_record)
                    if not public_path:
                        raise CryptoServiceError("RSA encryption requires a stored public key path.")
                    OpenSSLService.encrypt_rsa_2048(managed_file.original_path, output_path, public_path)
                else:
                    raise CryptoServiceError(f"Unsupported algorithm: {algorithm.name}")

            encrypted_hash = HashService.sha256_for_file(output_path)
            FileRepository.update(
                managed_file.id,
                encrypted_path=output_path,
                encrypted_hash=encrypted_hash,
                status="encrypted",
            )
            OperationRepository.update(
                operation.id,
                status="success",
                notes=f"{algorithm.name} encryption completed.",
            )
            performance = CryptoManagerService._save_performance(
                operation.id, metrics, managed_file.original_path, output_path
            )
            return OperationResult(
                managed_file=FileRepository.get_by_id(managed_file.id),
                operation=OperationRepository.get_by_id(operation.id),
                performance=performance,
                output_path=output_path,
                message="Encryption completed successfully.",
            )
        except Exception as exc:
            FileRepository.update(managed_file.id, status="failed")
            OperationRepository.update(operation.id, status="failed", error_message=str(exc))
            raise

    @staticmethod
    def decrypt_file(managed_file, algorithm, framework, key_record):
        CryptoManagerService.validate_combination(algorithm, key_record)
        if not managed_file.encrypted_path or not os.path.exists(managed_file.encrypted_path):
            raise CryptoServiceError("No encrypted file is registered for the selected record.")
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, "decrypt")
        output_name = f"decrypted_{Path(managed_file.original_name).name}"
        output_path = os.path.join(RuntimePaths.decrypted_dir, output_name)
        try:
            with MetricCollector() as metrics:
                if algorithm.name == "AES-256-CBC":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    CryptoManagerService._run_aes_decrypt(
                        framework.name, managed_file.encrypted_path, output_path, key_bytes
                    )
                elif algorithm.name == "RSA-2048":
                    _, private_path = KeyManagementService.key_paths(key_record)
                    if not private_path:
                        raise CryptoServiceError("RSA decryption requires a stored private key path.")
                    OpenSSLService.decrypt_rsa_2048(managed_file.encrypted_path, output_path, private_path)
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
            OperationRepository.update(
                operation.id,
                status="success" if integrity_ok else "failed",
                notes=notes,
                error_message=None if integrity_ok else "Decrypted hash does not match original hash.",
            )
            performance = CryptoManagerService._save_performance(
                operation.id, metrics, managed_file.encrypted_path, output_path
            )
            return OperationResult(
                managed_file=FileRepository.get_by_id(managed_file.id),
                operation=OperationRepository.get_by_id(operation.id),
                performance=performance,
                output_path=output_path,
                message=notes,
            )
        except Exception as exc:
            FileRepository.update(managed_file.id, status="failed")
            OperationRepository.update(operation.id, status="failed", error_message=str(exc))
            raise
