from Model.models import ManagedFile, db


class FileRepository:
    @staticmethod
    def create(
        original_name,
        original_path,
        encrypted_path=None,
        decrypted_path=None,
        original_hash=None,
        encrypted_hash=None,
        decrypted_hash=None,
        integrity_verified=None,
        status="plain",
    ):
        managed_file = ManagedFile(
            original_name=original_name,
            original_path=original_path,
            encrypted_path=encrypted_path,
            decrypted_path=decrypted_path,
            original_hash=original_hash,
            encrypted_hash=encrypted_hash,
            decrypted_hash=decrypted_hash,
            integrity_verified=integrity_verified,
            status=status,
        )
        db.session.add(managed_file)
        db.session.commit()
        return managed_file

    @staticmethod
    def get_by_id(file_id):
        return db.session.get(ManagedFile, file_id)

    @staticmethod
    def get_all():
        return ManagedFile.query.order_by(ManagedFile.created_at.desc()).all()

    @staticmethod
    def update(file_id, **kwargs):
        managed_file = db.session.get(ManagedFile, file_id)
        if not managed_file:
            return None
        for field, value in kwargs.items():
            if hasattr(managed_file, field):
                setattr(managed_file, field, value)
        db.session.commit()
        return managed_file

    @staticmethod
    def delete(file_id):
        managed_file = db.session.get(ManagedFile, file_id)
        if not managed_file:
            return False
        db.session.delete(managed_file)
        db.session.commit()
        return True
