import base64
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

from Business.errors import CryptoServiceError


class CryptographyCryptoService:
    AES_BLOCK_SIZE_BITS = 128
    GCM_NONCE_SIZE = 12
    GCM_TAG_SIZE = 16
    RSA_DIRECT_MAX_BYTES = 190

    @staticmethod
    def _build_operation_metadata_payload(algorithm_name, mode, nonce_b64=None, tag_b64=None, extra=None):
        payload = {
            "framework": "Cryptography",
            "algorithm": algorithm_name,
            "mode": mode,
        }
        if nonce_b64 is not None:
            payload["nonce_b64"] = nonce_b64
        if tag_b64 is not None:
            payload["auth_tag_b64"] = tag_b64
        if extra:
            payload.update(extra)
        return json.dumps(payload, sort_keys=True)

    @staticmethod
    def generate_symmetric_key(size_bytes):
        return secrets.token_bytes(size_bytes)

    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return public_pem, private_pem

    @staticmethod
    def load_public_key(public_pem):
        return serialization.load_pem_public_key(public_pem.encode("utf-8"))

    @staticmethod
    def load_private_key(private_pem):
        return serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        iv = secrets.token_bytes(16)
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()

        padder = padding.PKCS7(cls.AES_BLOCK_SIZE_BITS).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        mac_key = hashes.Hash(hashes.SHA256())
        mac_key.update(key_bytes + iv)
        derived_mac_key = mac_key.finalize()
        hmac_obj = HMAC(derived_mac_key, hashes.SHA256())
        hmac_obj.update(ciphertext)
        mac = hmac_obj.finalize()

        with open(output_path, "wb") as target_file:
            target_file.write(iv + mac + ciphertext)

        return {
            "iv_nonce": base64.b64encode(iv).decode("utf-8"),
            "auth_tag": base64.b64encode(mac).decode("utf-8"),
            "data_encryption_algorithm": "AES-256-CBC",
            "operation_metadata_json": cls._build_operation_metadata_payload(
                "AES-256-CBC",
                "CBC",
                nonce_b64=base64.b64encode(iv).decode("utf-8"),
                tag_b64=base64.b64encode(mac).decode("utf-8"),
                extra={"integrity": "HMAC-SHA256"},
            ),
        }

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        with open(input_path, "rb") as source_file:
            payload = source_file.read()
        if len(payload) < 48:
            raise CryptoServiceError("Invalid AES-CBC payload.")

        iv = payload[:16]
        mac = payload[16:48]
        ciphertext = payload[48:]

        mac_key = hashes.Hash(hashes.SHA256())
        mac_key.update(key_bytes + iv)
        derived_mac_key = mac_key.finalize()
        hmac_obj = HMAC(derived_mac_key, hashes.SHA256())
        hmac_obj.update(ciphertext)
        try:
            hmac_obj.verify(mac)
        except Exception as exc:
            raise CryptoServiceError("AES-CBC integrity verification failed.") from exc

        decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).decryptor()
        try:
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(cls.AES_BLOCK_SIZE_BITS).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        except ValueError as exc:
            raise CryptoServiceError("AES-CBC decryption failed. The key or payload is invalid.") from exc

        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)

        return {
            "iv_nonce": base64.b64encode(iv).decode("utf-8"),
            "auth_tag": base64.b64encode(mac).decode("utf-8"),
            "data_encryption_algorithm": "AES-256-CBC",
            "operation_metadata_json": cls._build_operation_metadata_payload(
                "AES-256-CBC",
                "CBC",
                nonce_b64=base64.b64encode(iv).decode("utf-8"),
                tag_b64=base64.b64encode(mac).decode("utf-8"),
                extra={"integrity": "HMAC-SHA256"},
            ),
        }

    @classmethod
    def encrypt_aes_256_gcm(cls, input_path, output_path, key_bytes):
        nonce = secrets.token_bytes(cls.GCM_NONCE_SIZE)
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()

        encrypted = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
        ciphertext = encrypted[:-cls.GCM_TAG_SIZE]
        tag = encrypted[-cls.GCM_TAG_SIZE:]

        with open(output_path, "wb") as target_file:
            target_file.write(ciphertext)

        return {
            "iv_nonce": base64.b64encode(nonce).decode("utf-8"),
            "auth_tag": base64.b64encode(tag).decode("utf-8"),
            "data_encryption_algorithm": "AES-256-GCM",
            "operation_metadata_json": cls._build_operation_metadata_payload(
                "AES-256-GCM",
                "GCM",
                nonce_b64=base64.b64encode(nonce).decode("utf-8"),
                tag_b64=base64.b64encode(tag).decode("utf-8"),
                extra={"integrity": "GCM tag"},
            ),
        }

    @classmethod
    def decrypt_aes_256_gcm(cls, input_path, output_path, key_bytes, nonce_b64, tag_b64):
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)

        with open(input_path, "rb") as source_file:
            ciphertext = source_file.read()

        try:
            plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext + tag, None)
        except InvalidTag as exc:
            raise CryptoServiceError("AES-GCM integrity verification failed.") from exc

        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)

        return {
            "iv_nonce": nonce_b64,
            "auth_tag": tag_b64,
            "data_encryption_algorithm": "AES-256-GCM",
            "operation_metadata_json": cls._build_operation_metadata_payload(
                "AES-256-GCM",
                "GCM",
                nonce_b64=nonce_b64,
                tag_b64=tag_b64,
                extra={"integrity": "GCM tag"},
            ),
        }

    @classmethod
    def encrypt_rsa_2048(cls, input_path, output_path, public_pem):
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()
        if len(plaintext) > cls.RSA_DIRECT_MAX_BYTES:
            raise CryptoServiceError(
                "RSA is only used for small demo files or key encryption. Use Hybrid RSA-AES for normal files."
            )

        public_key = cls.load_public_key(public_pem)
        ciphertext = public_key.encrypt(
            plaintext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        with open(output_path, "wb") as target_file:
            target_file.write(ciphertext)

    @classmethod
    def decrypt_rsa_2048(cls, input_path, output_path, private_pem):
        with open(input_path, "rb") as source_file:
            ciphertext = source_file.read()

        private_key = cls.load_private_key(private_pem)
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise CryptoServiceError("RSA decryption failed. The private key may be wrong.") from exc

        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)

    @classmethod
    def encrypt_hybrid_rsa_aes(cls, input_path, output_path, public_pem):
        data_key = cls.generate_symmetric_key(32)
        aes_metadata = cls.encrypt_aes_256_gcm(input_path, output_path, data_key)
        public_key = cls.load_public_key(public_pem)
        encrypted_data_key = public_key.encrypt(
            data_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        aes_metadata.update(
            {
                "encrypted_data_key": base64.b64encode(encrypted_data_key).decode("utf-8"),
                "key_wrap_algorithm": "RSA-OAEP-SHA256",
                "data_encryption_algorithm": "AES-256-GCM",
            }
        )
        return aes_metadata

    @classmethod
    def decrypt_hybrid_rsa_aes(cls, input_path, output_path, private_pem, encrypted_data_key_b64, nonce_b64, tag_b64):
        if not encrypted_data_key_b64:
            raise CryptoServiceError("Hybrid decryption requires the encrypted AES data key.")

        private_key = cls.load_private_key(private_pem)
        try:
            data_key = private_key.decrypt(
                base64.b64decode(encrypted_data_key_b64),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise CryptoServiceError("Hybrid decryption failed. The private key may be wrong.") from exc

        return cls.decrypt_aes_256_gcm(input_path, output_path, data_key, nonce_b64, tag_b64)
