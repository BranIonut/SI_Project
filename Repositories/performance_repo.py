from Model.models import Performance, db
from Repositories.common import delete_entity, get_by_id, update_entity


class PerformanceRepository:
    @staticmethod
    def create(
        operation_id,
        execution_time_ms,
        memory_usage_mb,
        input_size_bytes,
        output_size_bytes,
        time_per_byte_ms=None,
        time_per_byte_us=None,
        throughput_bytes_per_second=None,
        throughput_mib_per_second=None,
    ):
        metrics = Performance(
            operation_id=operation_id,
            execution_time_ms=execution_time_ms,
            memory_usage_mb=memory_usage_mb,
            input_size_bytes=input_size_bytes,
            output_size_bytes=output_size_bytes,
            time_per_byte_ms=time_per_byte_ms,
            time_per_byte_us=time_per_byte_us,
            throughput_bytes_per_second=throughput_bytes_per_second,
            throughput_mib_per_second=throughput_mib_per_second,
        )
        db.session.add(metrics)
        db.session.commit()
        return metrics

    @staticmethod
    def get_by_id(performance_id):
        return get_by_id(Performance, performance_id)

    @staticmethod
    def get_by_operation_id(operation_id):
        return Performance.query.filter_by(operation_id=operation_id).first()

    @staticmethod
    def get_all():
        return Performance.query.order_by(Performance.created_at.desc()).all()

    @staticmethod
    def update(performance_id, **kwargs):
        return update_entity(Performance, performance_id, ignore_none=True, **kwargs)

    @staticmethod
    def delete(performance_id):
        return delete_entity(Performance, performance_id)
