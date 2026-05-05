from Model.models import CryptoOperation, db, utc_now
from Repositories.common import assign_entity_fields, delete_entity, get_by_id


class OperationRepository:
    @staticmethod
    def create(
        file_id,
        algorithm_id,
        framework_id,
        key_id,
        operation_type,
        status,
        error_message=None,
        notes=None,
        started_at=None,
        finished_at=None,
    ):
        operation = CryptoOperation(
            file_id=file_id,
            algorithm_id=algorithm_id,
            framework_id=framework_id,
            key_id=key_id,
            operation_type=operation_type,
            status=status,
            error_message=error_message,
            notes=notes,
            started_at=started_at or utc_now(),
            finished_at=finished_at,
        )
        db.session.add(operation)
        db.session.commit()
        return operation

    @staticmethod
    def get_by_id(operation_id):
        return get_by_id(CryptoOperation, operation_id)

    @staticmethod
    def get_all():
        return CryptoOperation.query.order_by(CryptoOperation.started_at.desc()).all()

    @staticmethod
    def get_latest_successful_encrypt_for_file(file_id, algorithm_id=None, framework_id=None):
        query = CryptoOperation.query.filter_by(
            file_id=file_id,
            operation_type="encrypt",
            status="success",
        )
        if algorithm_id is not None:
            query = query.filter_by(algorithm_id=algorithm_id)
        if framework_id is not None:
            query = query.filter_by(framework_id=framework_id)
        return query.order_by(CryptoOperation.started_at.desc()).first()

    @staticmethod
    def update(operation_id, **kwargs):
        operation = db.session.get(CryptoOperation, operation_id)
        if not operation:
            return None
        assign_entity_fields(operation, **kwargs)
        if operation.finished_at is None and kwargs.get("status") in {"success", "failed"}:
            operation.finished_at = utc_now()
        db.session.commit()
        return operation

    @staticmethod
    def delete(operation_id):
        return delete_entity(CryptoOperation, operation_id)
