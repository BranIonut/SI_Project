from Model.models import Performance, db


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
        return db.session.get(Performance, performance_id)

    @staticmethod
    def get_by_operation_id(operation_id):
        return Performance.query.filter_by(operation_id=operation_id).first()

    @staticmethod
    def get_all():
        return Performance.query.order_by(Performance.created_at.desc()).all()

    @staticmethod
    def update(performance_id, **kwargs):
        performance = db.session.get(Performance, performance_id)
        if not performance:
            return None
        for field, value in kwargs.items():
            if hasattr(performance, field) and value is not None:
                setattr(performance, field, value)
        db.session.commit()
        return performance

    @staticmethod
    def delete(performance_id):
        performance = db.session.get(Performance, performance_id)
        if not performance:
            return False
        db.session.delete(performance)
        db.session.commit()
        return True
