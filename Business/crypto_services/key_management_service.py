import base64
import json
import os
import secrets

from Business.cryptography_service import CryptographyCryptoService
from Business.lab_algorithms import base64_lab, rsa_lab
from Business.lab_crypto_service import LabCryptoService
from Business.crypto_services.common import RuntimePaths
from Business.crypto_services.custom_service import CustomPythonService
from Business.crypto_services.openssl_service import OpenSSLService
from Business.errors import CryptoServiceError
from Repositories.key_repo import KeyRepository


class KeyManagementService:
    @staticmethod
    def _encode_bytes_for_storage(key_bytes):
        return base64_lab.encode_base64_bytes(key_bytes)

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
                key_bytes = OpenSSLService.generate_symmetric_key(32)
            elif framework_name == "cryptography":
                key_bytes = CryptographyCryptoService.generate_symmetric_key(32)
            else:
                key_bytes = CustomPythonService.generate_symmetric_key(32)
            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="symmetric",
                key_value=KeyManagementService._encode_bytes_for_storage(key_bytes),
            )

        if algorithm_name.startswith("DES"):
            if algorithm_name == "DES-LAB" or framework.name == "Lab Educational":
                key_bytes = secrets.token_bytes(8)
            else:
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
                key_value=KeyManagementService._encode_bytes_for_storage(key_bytes),
            )

        if algorithm_name == "RSA-LAB":
            demo_key = rsa_lab.generate_demo_key_pair()
            return KeyRepository.create(
                name=name,
                algorithm_id=algorithm.id,
                framework_id=framework.id,
                key_type="keypair",
                key_value=json.dumps(
                    {
                        "p": demo_key.p,
                        "q": demo_key.q,
                        "n": demo_key.n,
                        "phi": demo_key.phi,
                        "e": demo_key.e,
                        "d": demo_key.d,
                    },
                    sort_keys=True,
                ),
            )

        if algorithm_name.startswith("RSA") or algorithm_name.startswith("HYBRID"):
            if framework_name == "openssl":
                private_path = os.path.join(RuntimePaths.keys_dir, f"{name}_private.pem")
                public_path = os.path.join(RuntimePaths.keys_dir, f"{name}_public.pem")
                public_pem, private_pem = OpenSSLService.generate_rsa_key_pair(private_path, public_path)
            elif framework_name == "cryptography":
                public_pem, private_pem = CryptographyCryptoService.generate_rsa_key_pair()
                public_path = KeyManagementService._write_key_file(f"{name}_public.pem", public_pem)
                private_path = KeyManagementService._write_key_file(f"{name}_private.pem", private_pem)
            else:
                raise CryptoServiceError("RSA key generation is not available for this framework.")

            rsa_algorithm = algorithm if algorithm_name.startswith("RSA") else KeyRepository.resolve_rsa_algorithm()
            if not rsa_algorithm:
                raise CryptoServiceError("RSA-2048 algorithm is required before generating hybrid keys.")

            return KeyRepository.create(
                name=name,
                algorithm_id=rsa_algorithm.id,
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
        try:
            return base64_lab.decode_base64_bytes(key_record.key_value)
        except Exception:
            try:
                return base64.b64decode(key_record.key_value.encode("utf-8"))
            except Exception as exc:
                raise CryptoServiceError("Selected symmetric key contains invalid encoded key bytes.") from exc

    @staticmethod
    def key_paths(key_record):
        public_path = private_path = None
        if key_record.key_path and "|" in key_record.key_path:
            public_path, private_path = key_record.key_path.split("|", 1)
        return public_path, private_path
