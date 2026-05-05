import json

from Business.errors import CryptoServiceError
from Business.lab_algorithms import des_lab, rsa_lab


class LabCryptoService:
    @staticmethod
    def encrypt_des_file(input_path, output_path, key_bytes):
        try:
            des_lab.encrypt_file(input_path, output_path, key_bytes)
        except Exception as exc:
            raise CryptoServiceError(f"DES-LAB encryption failed: {exc}") from exc

    @staticmethod
    def decrypt_des_file(input_path, output_path, key_bytes):
        try:
            des_lab.decrypt_file(input_path, output_path, key_bytes)
        except Exception as exc:
            raise CryptoServiceError(f"DES-LAB decryption failed: {exc}") from exc

    @staticmethod
    def rsa_encrypt_file(input_path, output_path, e, n):
        if int(n) <= 255:
            raise CryptoServiceError("RSA-LAB requires n > 255 for byte-by-byte file encryption.")
        try:
            rsa_lab.rsa_encrypt_file(input_path, output_path, e, n)
        except Exception as exc:
            raise CryptoServiceError(f"RSA-LAB encryption failed: {exc}") from exc

    @staticmethod
    def rsa_decrypt_file(input_path, output_path, d, n):
        try:
            rsa_lab.rsa_decrypt_file(input_path, output_path, d, n)
        except Exception as exc:
            raise CryptoServiceError(f"RSA-LAB decryption failed: {exc}") from exc

    @staticmethod
    def parse_rsa_key_material(key_record):
        if not key_record.key_value:
            raise CryptoServiceError("Selected RSA-LAB key has no stored key parameters.")
        try:
            payload = json.loads(key_record.key_value)
        except json.JSONDecodeError as exc:
            raise CryptoServiceError("Selected RSA-LAB key contains invalid JSON key parameters.") from exc

        missing = [field for field in ("n", "e", "d") if field not in payload]
        if missing:
            raise CryptoServiceError(f"Selected RSA-LAB key is missing parameters: {', '.join(missing)}.")

        try:
            return int(payload["n"]), int(payload["e"]), int(payload["d"])
        except (TypeError, ValueError) as exc:
            raise CryptoServiceError("Selected RSA-LAB key contains non-integer RSA parameters.") from exc
