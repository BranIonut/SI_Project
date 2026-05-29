import os
import sys


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Business.crypto_service import KeyManagementService
from Model.models import app, init_db
from Repositories.algorithm_repo import AlgorithmRepository
from Repositories.framework_repo import FrameworkRepository
from Repositories.key_repo import KeyRepository


DEMO_KEYS = (
    ("demo_openssl_aes_256_cbc", "AES-256-CBC", "OpenSSL"),
    ("demo_openssl_des_cbc", "DES-CBC", "OpenSSL"),
    ("demo_openssl_rsa_2048", "RSA-2048", "OpenSSL"),
    ("demo_crypto_aes_256_cbc", "AES-256-CBC", "Cryptography"),
    ("demo_crypto_aes_256_gcm", "AES-256-GCM", "Cryptography"),
    ("demo_crypto_rsa_2048", "RSA-2048", "Cryptography"),
    ("demo_lab_des", "DES-LAB", "Lab Educational"),
    ("demo_lab_rsa", "RSA-LAB", "Lab Educational"),
)


def seed_manual_keys():
    init_db(seed=True)
    created = []
    skipped = []

    with app.app_context():
        for key_name, algorithm_name, framework_name in DEMO_KEYS:
            if KeyRepository.get_by_name(key_name):
                skipped.append(key_name)
                continue

            algorithm = AlgorithmRepository.get_by_name(algorithm_name)
            framework = FrameworkRepository.get_by_name(framework_name)
            if not algorithm or not framework:
                skipped.append(key_name)
                continue

            KeyManagementService.generate_key(key_name, algorithm, framework)
            created.append(key_name)

    return created, skipped


if __name__ == "__main__":
    created_keys, skipped_keys = seed_manual_keys()
    print(f"Created: {len(created_keys)}")
    for name in created_keys:
        print(f"  + {name}")
    print(f"Skipped: {len(skipped_keys)}")
    for name in skipped_keys:
        print(f"  = {name}")
