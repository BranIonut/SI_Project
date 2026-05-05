import os
import shutil

from Business.crypto_services.common import HashService, RuntimePaths
from Repositories.file_repo import FileRepository


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
            reset_processed_fields = existing.original_hash != original_hash
            return FileRepository.update(
                existing.id,
                original_name=original_name,
                original_path=target_path,
                original_hash=original_hash,
                status="plain" if reset_processed_fields else existing.status,
                encrypted_path=None if reset_processed_fields else existing.encrypted_path,
                encrypted_hash=None if reset_processed_fields else existing.encrypted_hash,
                decrypted_path=None if reset_processed_fields else existing.decrypted_path,
                decrypted_hash=None if reset_processed_fields else existing.decrypted_hash,
                integrity_verified=None if reset_processed_fields else existing.integrity_verified,
            )
        return FileRepository.create(
            original_name=original_name,
            original_path=target_path,
            original_hash=original_hash,
            status="plain",
        )
