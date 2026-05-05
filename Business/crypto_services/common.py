import os
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any

from Business.lab_algorithms import hash_lab
from Business.crypto_services.constants import STATUS_FAILED, STATUS_SUCCESS
from Model.models import BASE_DIR, utc_now

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


@dataclass
class OperationResult:
    managed_file: Any
    operation: Any
    performance: Any
    output_path: str
    message: str


@dataclass
class NormalizedPerformanceMetrics:
    execution_time_ms: float
    memory_usage_mb: float
    input_size_bytes: int
    output_size_bytes: int
    time_per_byte_ms: float | None
    time_per_byte_us: float | None
    throughput_bytes_per_second: float | None
    throughput_mib_per_second: float | None


class HashService:
    @staticmethod
    def sha256_for_file(file_path):
        return hash_lab.sha256_file(file_path)

    @classmethod
    def hashes_for_paths(cls, **named_paths):
        return {
            name: cls.sha256_for_file(path)
            for name, path in named_paths.items()
            if path and os.path.exists(path)
        }

    @staticmethod
    def is_integrity_verified(original_hash, candidate_hash):
        return bool(original_hash and original_hash == candidate_hash)


class RuntimePaths:
    original_dir = os.path.join(BASE_DIR, "data", "original")
    encrypted_dir = os.path.join(BASE_DIR, "data", "encrypted")
    decrypted_dir = os.path.join(BASE_DIR, "data", "decrypted")
    keys_dir = os.path.join(BASE_DIR, "data", "keys")

    @staticmethod
    def file_size_or_zero(file_path):
        return os.path.getsize(file_path) if file_path and os.path.exists(file_path) else 0

    @classmethod
    def build_encrypted_output_path(cls, managed_file, algorithm):
        safe_algorithm = algorithm.name.lower().replace("-", "_").replace(" ", "_")
        output_name = f"{os.path.basename(managed_file.original_name)}.{safe_algorithm}.enc"
        return os.path.join(cls.encrypted_dir, output_name)

    @classmethod
    def build_decrypted_output_path(cls, managed_file):
        return os.path.join(cls.decrypted_dir, f"decrypted_{os.path.basename(managed_file.original_name)}")


class MetricCollector:
    def __enter__(self):
        self.started_at = utc_now()
        self.start_time = time.perf_counter()
        tracemalloc.start()
        self.process = psutil.Process(os.getpid()) if psutil else None
        self.start_rss = self.process.memory_info().rss if self.process else 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        end_rss = self.process.memory_info().rss if self.process else 0
        rss_delta = max(end_rss - self.start_rss, 0)
        self.finished_at = utc_now()
        self.execution_time_ms = (time.perf_counter() - self.start_time) * 1000
        self.memory_usage_mb = max(peak, current, rss_delta) / (1024 * 1024)


class PerformanceMetricCalculator:
    @staticmethod
    def calculate(execution_time_ms, memory_usage_mb, input_size_bytes, output_size_bytes):
        time_per_byte_ms = None
        time_per_byte_us = None
        throughput_bytes_per_second = None
        throughput_mib_per_second = None

        if input_size_bytes > 0:
            time_per_byte_ms = execution_time_ms / input_size_bytes
            time_per_byte_us = (execution_time_ms * 1000) / input_size_bytes

        if input_size_bytes > 0 and execution_time_ms > 0:
            throughput_bytes_per_second = input_size_bytes / (execution_time_ms / 1000)
            throughput_mib_per_second = throughput_bytes_per_second / (1024 * 1024)

        return NormalizedPerformanceMetrics(
            execution_time_ms=execution_time_ms,
            memory_usage_mb=memory_usage_mb,
            input_size_bytes=input_size_bytes,
            output_size_bytes=output_size_bytes,
            time_per_byte_ms=time_per_byte_ms,
            time_per_byte_us=time_per_byte_us,
            throughput_bytes_per_second=throughput_bytes_per_second,
            throughput_mib_per_second=throughput_mib_per_second,
        )

    @classmethod
    def calculate_from_paths(cls, execution_time_ms, memory_usage_mb, input_path, output_path):
        return cls.calculate(
            execution_time_ms=execution_time_ms,
            memory_usage_mb=memory_usage_mb,
            input_size_bytes=RuntimePaths.file_size_or_zero(input_path),
            output_size_bytes=RuntimePaths.file_size_or_zero(output_path),
        )


class OperationStateResolver:
    @staticmethod
    def completion_status(is_successful):
        return STATUS_SUCCESS if is_successful else STATUS_FAILED
