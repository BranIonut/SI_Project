import base64
import binascii
import hashlib
import os
import secrets
import shutil
import subprocess
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - optional fallback
    psutil = None

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
    def generate_symmetric_key(size_bytes):
        return secrets.token_bytes(size_bytes)

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
    def _encrypt_block_cipher(cls, cipher_name, input_path, output_path, key_bytes, iv_size, extra_args=None):
        key_hex = binascii.hexlify(key_bytes).decode("utf-8")
        iv_bytes = secrets.token_bytes(iv_size)
        iv_hex = binascii.hexlify(iv_bytes).decode("utf-8")
        command = ["enc", f"-{cipher_name}", "-in", input_path, "-out", output_path, "-K", key_hex, "-iv", iv_hex]
        if extra_args:
            command.extend(extra_args)
        cls.run_command(
            command
        )
        with open(output_path, "rb") as encrypted_file:
            payload = encrypted_file.read()
        with open(output_path, "wb") as encrypted_file:
            encrypted_file.write(iv_bytes + payload)

    @classmethod
    def _decrypt_block_cipher(cls, cipher_name, input_path, output_path, key_bytes, iv_size, extra_args=None):
        with open(input_path, "rb") as encrypted_file:
            iv_bytes = encrypted_file.read(iv_size)
            payload = encrypted_file.read()
        temp_payload_path = f"{output_path}.openssl.tmp"
        with open(temp_payload_path, "wb") as temp_payload:
            temp_payload.write(payload)
        try:
            key_hex = binascii.hexlify(key_bytes).decode("utf-8")
            iv_hex = binascii.hexlify(iv_bytes).decode("utf-8")
            command = [
                "enc",
                "-d",
                f"-{cipher_name}",
                "-in",
                temp_payload_path,
                "-out",
                output_path,
                "-K",
                key_hex,
                "-iv",
                iv_hex,
            ]
            if extra_args:
                command.extend(extra_args)
            cls.run_command(
                command
            )
        finally:
            if os.path.exists(temp_payload_path):
                os.remove(temp_payload_path)

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_block_cipher("aes-256-cbc", input_path, output_path, key_bytes, 16)

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_block_cipher("aes-256-cbc", input_path, output_path, key_bytes, 16)

    @classmethod
    def encrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_block_cipher(
            "des-cbc",
            input_path,
            output_path,
            key_bytes,
            8,
            extra_args=["-provider", "default", "-provider", "legacy"],
        )

    @classmethod
    def decrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_block_cipher(
            "des-cbc",
            input_path,
            output_path,
            key_bytes,
            8,
            extra_args=["-provider", "default", "-provider", "legacy"],
        )

    @classmethod
    def encrypt_rsa_2048(cls, input_path, output_path, public_key_path):
        if os.path.getsize(input_path) > cls.MAX_RSA_INPUT_BYTES:
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
            ["pkeyutl", "-decrypt", "-inkey", private_key_path, "-in", input_path, "-out", output_path]
        )


class CustomPythonService:
    @staticmethod
    def generate_symmetric_key(size_bytes):
        return secrets.token_bytes(size_bytes)

    @staticmethod
    def _xor_bytes(left, right):
        return bytes(a ^ b for a, b in zip(left, right))

    @staticmethod
    def _pkcs7_pad(data, block_size):
        padding_size = block_size - (len(data) % block_size)
        return data + bytes([padding_size]) * padding_size

    @staticmethod
    def _pkcs7_unpad(data, block_size):
        if not data or len(data) % block_size != 0:
            raise CryptoServiceError("Invalid padded data.")
        padding_size = data[-1]
        if padding_size < 1 or padding_size > block_size:
            raise CryptoServiceError("Invalid padding size.")
        if data[-padding_size:] != bytes([padding_size]) * padding_size:
            raise CryptoServiceError("Invalid PKCS7 padding.")
        return data[:-padding_size]

    @staticmethod
    def _feistel_round_function(key_bytes, round_index, data, output_size):
        digest = hashlib.sha256(key_bytes + bytes([round_index]) + data).digest()
        return digest[:output_size]

    @classmethod
    def _encrypt_block(cls, block, key_bytes, rounds):
        half = len(block) // 2
        left = block[:half]
        right = block[half:]
        for round_index in range(rounds):
            function_output = cls._feistel_round_function(key_bytes, round_index, right, half)
            left, right = right, cls._xor_bytes(left, function_output)
        return left + right

    @classmethod
    def _decrypt_block(cls, block, key_bytes, rounds):
        half = len(block) // 2
        left = block[:half]
        right = block[half:]
        for round_index in reversed(range(rounds)):
            function_output = cls._feistel_round_function(key_bytes, round_index, left, half)
            left, right = cls._xor_bytes(right, function_output), left
        return left + right

    @classmethod
    def _encrypt_cbc(cls, input_path, output_path, key_bytes, block_size, rounds):
        iv = secrets.token_bytes(block_size)
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()
        padded_plaintext = cls._pkcs7_pad(plaintext, block_size)
        previous = iv
        ciphertext_blocks = [iv]
        for index in range(0, len(padded_plaintext), block_size):
            block = padded_plaintext[index:index + block_size]
            xored = cls._xor_bytes(block, previous)
            encrypted = cls._encrypt_block(xored, key_bytes, rounds)
            ciphertext_blocks.append(encrypted)
            previous = encrypted
        with open(output_path, "wb") as target_file:
            target_file.write(b"".join(ciphertext_blocks))

    @classmethod
    def _decrypt_cbc(cls, input_path, output_path, key_bytes, block_size, rounds):
        with open(input_path, "rb") as source_file:
            payload = source_file.read()
        if len(payload) < block_size * 2 or len(payload) % block_size != 0:
            raise CryptoServiceError("Invalid encrypted payload.")
        iv = payload[:block_size]
        ciphertext = payload[block_size:]
        previous = iv
        plaintext_blocks = []
        for index in range(0, len(ciphertext), block_size):
            block = ciphertext[index:index + block_size]
            decrypted = cls._decrypt_block(block, key_bytes, rounds)
            plaintext_blocks.append(cls._xor_bytes(decrypted, previous))
            previous = block
        plaintext = cls._pkcs7_unpad(b"".join(plaintext_blocks), block_size)
        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_cbc(input_path, output_path, key_bytes, block_size=16, rounds=8)

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_cbc(input_path, output_path, key_bytes, block_size=16, rounds=8)

    @classmethod
    def encrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_cbc(input_path, output_path, key_bytes, block_size=8, rounds=6)

    @classmethod
    def decrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_cbc(input_path, output_path, key_bytes, block_size=8, rounds=6)


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
            key_bytes = (
                OpenSSLService.generate_symmetric_key(32)
                if framework_name == "openssl"
                else CustomPythonService.generate_symmetric_key(32)
            )
            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=base64.b64encode(key_bytes).decode("utf-8"),
            )

        if algorithm_name.startswith("DES"):
            key_bytes = (
                OpenSSLService.generate_symmetric_key(8)
                if framework_name == "openssl"
                else CustomPythonService.generate_symmetric_key(8)
            )
            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=base64.b64encode(key_bytes).decode("utf-8"),
            )

        if algorithm_name.startswith("RSA"):
            if framework_name != "openssl":
                raise CryptoServiceError("RSA key generation is supported only with OpenSSL.")
            private_path = os.path.join(RuntimePaths.keys_dir, f"{name}_private.pem")
            public_path = os.path.join(RuntimePaths.keys_dir, f"{name}_public.pem")
            public_pem, private_pem = OpenSSLService.generate_rsa_key_pair(private_path, public_path)
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
            (
                item
                for item in FileRepository.get_all()
                if os.path.abspath(item.original_path) == os.path.abspath(target_path)
            ),
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
            raise CryptoServiceError("Symmetric operations require a symmetric key.")
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
    def _run_symmetric_encrypt(algorithm_name, framework_name, input_path, output_path, key_bytes):
        if framework_name == "OpenSSL":
            if algorithm_name == "AES-256-CBC":
                OpenSSLService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                OpenSSLService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == "Custom":
            if algorithm_name == "AES-256-CBC":
                CustomPythonService.encrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                CustomPythonService.encrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom algorithm: {algorithm_name}")
        else:
            raise CryptoServiceError(f"Unsupported framework: {framework_name}")

    @staticmethod
    def _run_symmetric_decrypt(algorithm_name, framework_name, input_path, output_path, key_bytes):
        if framework_name == "OpenSSL":
            if algorithm_name == "AES-256-CBC":
                OpenSSLService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                OpenSSLService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported OpenSSL algorithm: {algorithm_name}")
        elif framework_name == "Custom":
            if algorithm_name == "AES-256-CBC":
                CustomPythonService.decrypt_aes_256_cbc(input_path, output_path, key_bytes)
            elif algorithm_name == "DES-CBC":
                CustomPythonService.decrypt_des_cbc(input_path, output_path, key_bytes)
            else:
                raise CryptoServiceError(f"Unsupported Custom algorithm: {algorithm_name}")
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
                if algorithm.type == "symmetric":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    CryptoManagerService._run_symmetric_encrypt(
                        algorithm.name, framework.name, managed_file.original_path, output_path, key_bytes
                    )
                elif algorithm.name == "RSA-2048":
                    if framework.name != "OpenSSL":
                        raise CryptoServiceError("RSA encryption is supported only with OpenSSL.")
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
            OperationRepository.update(operation.id, status="success", notes=f"{algorithm.name} encryption completed.")
            performance = CryptoManagerService._save_performance(
                operation.id, metrics, managed_file.original_path, output_path
            )
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
        CryptoManagerService.validate_combination(algorithm, key_record)
        if not managed_file.encrypted_path or not os.path.exists(managed_file.encrypted_path):
            raise CryptoServiceError("No encrypted file is registered for the selected record.")
        operation = CryptoManagerService._create_operation(managed_file, algorithm, framework, key_record, "decrypt")
        output_path = os.path.join(RuntimePaths.decrypted_dir, f"decrypted_{Path(managed_file.original_name).name}")
        try:
            with MetricCollector() as metrics:
                if algorithm.type == "symmetric":
                    key_bytes = KeyManagementService.decode_symmetric_key(key_record)
                    CryptoManagerService._run_symmetric_decrypt(
                        algorithm.name, framework.name, managed_file.encrypted_path, output_path, key_bytes
                    )
                elif algorithm.name == "RSA-2048":
                    if framework.name != "OpenSSL":
                        raise CryptoServiceError("RSA decryption is supported only with OpenSSL.")
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
                performance=PerformanceRepository.get_by_id(performance.id),
                output_path=output_path,
                message=notes,
            )
        except Exception as exc:
            FileRepository.update(managed_file.id, status="failed")
            OperationRepository.update(operation.id, status="failed", error_message=str(exc))
            raise
