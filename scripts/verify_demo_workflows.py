import os
import sys


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Business.crypto_service import CryptoManagerService, CryptoServiceError, FileManagementService
from Model.models import app, init_db
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.file_repo import FileRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.key_repo import KeyRepository
from scripts.seed_manual_keys import seed_manual_keys


DEMO_WORKFLOWS = (
    (
        "OpenSSL AES-256-CBC",
        "data/manual_verification/normal_aes_demo.txt",
        "AES-256-CBC",
        "OpenSSL",
        "demo_openssl_aes_256_cbc",
    ),
    (
        "Cryptography AES-256-GCM",
        "data/manual_verification/crypto_demo.txt",
        "AES-256-GCM",
        "Cryptography",
        "demo_crypto_aes_256_gcm",
    ),
    (
        "OpenSSL RSA-2048",
        "data/manual_verification/small_rsa_demo.txt",
        "RSA-2048",
        "OpenSSL",
        "demo_openssl_rsa_2048",
    ),
    (
        "Lab Educational DES-LAB",
        "data/manual_verification/normal_demo.txt",
        "DES-LAB",
        "Lab Educational",
        "demo_lab_des",
    ),
)


BAD_COMBINATIONS = (
    (
        "Wrong framework for key",
        "data/manual_verification/normal_aes_demo.txt",
        "AES-256-CBC",
        "OpenSSL",
        "demo_crypto_aes_256_cbc",
    ),
    (
        "Wrong algorithm for key",
        "data/manual_verification/crypto_demo.txt",
        "AES-256-GCM",
        "Cryptography",
        "demo_crypto_aes_256_cbc",
    ),
    (
        "RSA rejects large direct file",
        "data/manual_verification/large_rsa_demo.txt",
        "RSA-2048",
        "OpenSSL",
        "demo_openssl_rsa_2048",
    ),
)


def _resolve(path, algorithm_name, framework_name, key_name):
    managed_file = FileManagementService.register_file(os.path.join(PROJECT_ROOT, path))
    algorithm = AlgorithmRepository.get_by_name(algorithm_name)
    framework = FrameworkRepository.get_by_name(framework_name)
    key_record = KeyRepository.get_by_name(key_name)
    return managed_file, algorithm, framework, key_record


def verify_demo_workflows():
    init_db(seed=True)
    seed_manual_keys()

    with app.app_context():
        for label, path, algorithm_name, framework_name, key_name in DEMO_WORKFLOWS:
            managed_file, algorithm, framework, key_record = _resolve(path, algorithm_name, framework_name, key_name)
            encrypted = CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
            decrypted = CryptoManagerService.decrypt_file(encrypted.managed_file, algorithm, framework, key_record)
            refreshed = FileRepository.get_by_id(managed_file.id)
            if refreshed.original_hash != refreshed.decrypted_hash or refreshed.integrity_verified is not True:
                raise AssertionError(f"{label} failed integrity verification.")
            print(f"OK: {label} -> {decrypted.output_path}")

        for label, path, algorithm_name, framework_name, key_name in BAD_COMBINATIONS:
            managed_file, algorithm, framework, key_record = _resolve(path, algorithm_name, framework_name, key_name)
            try:
                CryptoManagerService.encrypt_file(managed_file, algorithm, framework, key_record)
            except CryptoServiceError as exc:
                print(f"OK: {label} rejected -> {exc}")
            else:
                raise AssertionError(f"{label} was not rejected.")


if __name__ == "__main__":
    verify_demo_workflows()
