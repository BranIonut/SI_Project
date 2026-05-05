import binascii
import os
import secrets
import shutil
import subprocess

from Business.errors import CryptoServiceError


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
        raise CryptoServiceError("OpenSSL executable not found. Set OPENSSL_BIN or install OpenSSL.")

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
        cls.run_command(command)
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
            command = ["enc", "-d", f"-{cipher_name}", "-in", temp_payload_path, "-out", output_path, "-K", key_hex, "-iv", iv_hex]
            if extra_args:
                command.extend(extra_args)
            cls.run_command(command)
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
        cls._encrypt_block_cipher("des-cbc", input_path, output_path, key_bytes, 8, extra_args=["-provider", "default", "-provider", "legacy"])

    @classmethod
    def decrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_block_cipher("des-cbc", input_path, output_path, key_bytes, 8, extra_args=["-provider", "default", "-provider", "legacy"])

    @classmethod
    def encrypt_rsa_2048(cls, input_path, output_path, public_key_path):
        if os.path.getsize(input_path) > cls.MAX_RSA_INPUT_BYTES:
            raise CryptoServiceError("RSA is only used for small demo files or key encryption. Use Hybrid RSA-AES for normal file encryption.")
        cls.run_command([
            "pkeyutl", "-encrypt", "-pubin", "-inkey", public_key_path, "-in", input_path, "-out", output_path,
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
        ])

    @classmethod
    def decrypt_rsa_2048(cls, input_path, output_path, private_key_path):
        cls.run_command([
            "pkeyutl", "-decrypt", "-inkey", private_key_path, "-in", input_path, "-out", output_path,
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
        ])
