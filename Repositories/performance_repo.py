from Model.models import Performance, db


class PerformanceRepository:
    @staticmethod
    def create(file_id, algorithm_id, framework_id, operation, time_ms, mem_kb):
        metrics = Performance(
            file_id=file_id,
            algorithm_id=algorithm_id,
            framework_id=framework_id,
            operation=operation,
            exec_time_ms=time_ms,
            used_mem_kb=mem_kb
        )
        db.session.add(metrics)
        db.session.commit()
        return metrics
