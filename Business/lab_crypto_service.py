import json

from Business.errors import CryptoServiceError
from Business.lab_algorithms import base64_lab, des_lab, hash_lab, rsa_lab, signature_pki_lab


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
    def sha256_file(path):
        return hash_lab.sha256_file(path)

    @staticmethod
    def hmac_sha1_for_file(path, key_bytes):
        with open(path, "rb") as handle:
            return hash_lab.hmac_sha1(key_bytes, handle.read())

    @staticmethod
    def base64_encode_file(input_path, output_path):
        base64_lab.encode_file_to_base64(input_path, output_path)

    @staticmethod
    def base64_decode_file(input_path, output_path):
        base64_lab.decode_file_from_base64(input_path, output_path)

    @staticmethod
    def create_signed_document(message, n, e, d):
        return signature_pki_lab.PKISystem(n, e, d).create_signed_doc(message)

    @staticmethod
    def issue_certificate(owner_name, n, e, issuer="Lab Educational CA"):
        return signature_pki_lab.CertificateAuthority(issuer).issue_certificate(owner_name, (n, e))

    @staticmethod
    def verify_signed_document(signed_doc, certificate):
        n, e = certificate.public_key
        return signature_pki_lab.PKISystem(n, e, 1).verify_with_cert(signed_doc, certificate)

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
