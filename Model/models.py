import os
from datetime import datetime, timezone

from Business.crypto_services.constants import (
    ALGORITHM_AES_256_CBC,
    ALGORITHM_AES_256_GCM,
    ALGORITHM_DES_CBC,
    ALGORITHM_DES_LAB,
    ALGORITHM_HYBRID_RSA_AES,
    ALGORITHM_RSA_2048,
    ALGORITHM_RSA_LAB,
    FRAMEWORK_CRYPTOGRAPHY,
    FRAMEWORK_CUSTOM_EDUCATIONAL,
    FRAMEWORK_CUSTOM_LEGACY,
    FRAMEWORK_LAB_EDUCATIONAL,
    FRAMEWORK_OPENSSL,
)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "instance", "kms_local.db")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DEFAULT_DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


def utc_now():
    return datetime.now(timezone.utc)


class Framework(db.Model):
    __tablename__ = "frameworks"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    display_name = db.Column(db.String(150))
    type = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)


class Algorithm(db.Model):
    __tablename__ = "algorithms"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    type = db.Column(db.String(20), nullable=False)
    mode = db.Column(db.String(50))
    key_size = db.Column(db.Integer, nullable=False)
    framework_id = db.Column(db.Integer, db.ForeignKey("frameworks.id"))
    description = db.Column(db.Text)

    framework = db.relationship("Framework", backref="algorithms")


class Key(db.Model):
    __tablename__ = "keys"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    algorithm_id = db.Column(db.Integer, db.ForeignKey("algorithms.id"), nullable=False)
    framework_id = db.Column(db.Integer, db.ForeignKey("frameworks.id"), nullable=False)
    key_type = db.Column(db.String(20), nullable=False)
    key_value = db.Column(db.Text)
    key_path = db.Column(db.String(255))
    public_key_value = db.Column(db.Text)
    private_key_value = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    is_active = db.Column(db.Boolean, nullable=False, default=True)

    algorithm = db.relationship("Algorithm", backref="keys")
    framework = db.relationship("Framework", backref="keys")


class ManagedFile(db.Model):
    __tablename__ = "managed_files"

    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    original_path = db.Column(db.String(500), nullable=False)
    encrypted_path = db.Column(db.String(500))
    decrypted_path = db.Column(db.String(500))
    original_hash = db.Column(db.String(64))
    encrypted_hash = db.Column(db.String(64))
    decrypted_hash = db.Column(db.String(64))
    integrity_verified = db.Column(db.Boolean)
    status = db.Column(db.String(20), nullable=False, default="plain")
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    updated_at = db.Column(db.DateTime, nullable=False, default=utc_now, onupdate=utc_now)


class CryptoOperation(db.Model):
    __tablename__ = "crypto_operations"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("managed_files.id"), nullable=False)
    algorithm_id = db.Column(db.Integer, db.ForeignKey("algorithms.id"), nullable=False)
    framework_id = db.Column(db.Integer, db.ForeignKey("frameworks.id"), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey("keys.id"), nullable=False)
    operation_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    error_message = db.Column(db.Text)
    notes = db.Column(db.Text)
    encrypted_data_key = db.Column(db.Text)
    iv_nonce = db.Column(db.Text)
    auth_tag = db.Column(db.Text)
    key_wrap_algorithm = db.Column(db.String(100))
    data_encryption_algorithm = db.Column(db.String(100))
    operation_metadata_json = db.Column(db.Text)
    started_at = db.Column(db.DateTime, nullable=False, default=utc_now)
    finished_at = db.Column(db.DateTime)

    managed_file = db.relationship("ManagedFile", backref="operations")
    algorithm = db.relationship("Algorithm", backref="operations")
    framework = db.relationship("Framework", backref="operations")
    key = db.relationship("Key", backref="operations")


class Performance(db.Model):
    __tablename__ = "performances"

    id = db.Column(db.Integer, primary_key=True)
    operation_id = db.Column(
        db.Integer, db.ForeignKey("crypto_operations.id"), nullable=False, unique=True
    )
    execution_time_ms = db.Column(db.Float, nullable=False)
    memory_usage_mb = db.Column(db.Float, nullable=False)
    input_size_bytes = db.Column(db.Integer, nullable=False)
    output_size_bytes = db.Column(db.Integer, nullable=False)
    time_per_byte_ms = db.Column(db.Float)
    time_per_byte_us = db.Column(db.Float)
    throughput_bytes_per_second = db.Column(db.Float)
    throughput_mib_per_second = db.Column(db.Float)
    created_at = db.Column(db.DateTime, nullable=False, default=utc_now)

    operation = db.relationship("CryptoOperation", backref="performance", uselist=False)


def ensure_runtime_directories(base_dir=None):
    root = base_dir or BASE_DIR
    for relative_path in (
        "instance",
        os.path.join("data", "original"),
        os.path.join("data", "encrypted"),
        os.path.join("data", "decrypted"),
        os.path.join("data", "keys"),
    ):
        os.makedirs(os.path.join(root, relative_path), exist_ok=True)


def _ensure_column(table_name, column_name, ddl_fragment):
    inspector = inspect(db.engine)
    existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
    if column_name in existing_columns:
        return
    with db.engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl_fragment}"))


def migrate_schema():
    framework_columns = (
        ("display_name", "VARCHAR(150)"),
        ("description", "TEXT"),
    )
    operation_columns = (
        ("encrypted_data_key", "TEXT"),
        ("iv_nonce", "TEXT"),
        ("auth_tag", "TEXT"),
        ("key_wrap_algorithm", "VARCHAR(100)"),
        ("data_encryption_algorithm", "VARCHAR(100)"),
        ("operation_metadata_json", "TEXT"),
    )
    performance_columns = (
        ("time_per_byte_ms", "FLOAT"),
        ("time_per_byte_us", "FLOAT"),
        ("throughput_bytes_per_second", "FLOAT"),
        ("throughput_mib_per_second", "FLOAT"),
    )

    for name, ddl in framework_columns:
        _ensure_column("frameworks", name, ddl)
    for name, ddl in operation_columns:
        _ensure_column("crypto_operations", name, ddl)
    for name, ddl in performance_columns:
        _ensure_column("performances", name, ddl)


def _upsert_named_record(model_cls, item):
    record = model_cls.query.filter_by(name=item["name"]).first()
    if not record:
        db.session.add(model_cls(**item))
        return None
    for field, value in item.items():
        if field != "name":
            setattr(record, field, value)
    return record


def _normalize_legacy_custom_framework():
    canonical = Framework.query.filter_by(name=FRAMEWORK_CUSTOM_LEGACY).first()
    if canonical is None:
        canonical = Framework.query.filter_by(name="Custom").first()
    if canonical is None:
        canonical = Framework.query.filter_by(name=FRAMEWORK_CUSTOM_EDUCATIONAL).first()
    if canonical is None:
        return

    canonical.name = FRAMEWORK_CUSTOM_LEGACY
    canonical.display_name = FRAMEWORK_CUSTOM_LEGACY
    canonical.type = "Legacy / educational Python implementation"
    canonical.version = None
    canonical.description = (
        "Legacy educational implementation kept for backwards compatibility. "
        "Not part of the main encryption workflow and not production-grade."
    )


def seed_defaults():
    framework_defaults = (
        {
            "name": FRAMEWORK_OPENSSL,
            "display_name": FRAMEWORK_OPENSSL,
            "type": "CLI / subprocess",
            "version": None,
            "description": "Required cryptographic framework used through subprocess calls for file encryption and decryption.",
        },
        {
            "name": FRAMEWORK_CRYPTOGRAPHY,
            "display_name": "Python cryptography",
            "type": "Python library",
            "version": None,
            "description": "Real Python cryptography framework used as an alternative to OpenSSL for encryption/decryption and performance comparison.",
        },
        {
            "name": FRAMEWORK_LAB_EDUCATIONAL,
            "display_name": FRAMEWORK_LAB_EDUCATIONAL,
            "type": "Laboratory / educational algorithms",
            "version": None,
            "description": "Educational implementations based on the cryptography laboratory code. Used as an alternative framework for learning and performance comparison with OpenSSL. Not production-grade.",
        },
        {
            "name": FRAMEWORK_CUSTOM_LEGACY,
            "display_name": FRAMEWORK_CUSTOM_LEGACY,
            "type": "Legacy / educational Python implementation",
            "version": None,
            "description": "Legacy educational implementation kept for backwards compatibility. Not part of the main encryption workflow and not production-grade.",
        },
    )

    _normalize_legacy_custom_framework()

    for item in framework_defaults:
        _upsert_named_record(Framework, item)

    db.session.flush()

    defaults = (
        {
            "name": ALGORITHM_AES_256_CBC,
            "type": "symmetric",
            "mode": "CBC",
            "key_size": 256,
            "description": "AES-256-CBC file encryption through OpenSSL and Python cryptography.",
        },
        {
            "name": ALGORITHM_AES_256_GCM,
            "type": "symmetric",
            "mode": "GCM",
            "key_size": 256,
            "description": "Authenticated AES encryption using Python cryptography.",
        },
        {
            "name": ALGORITHM_DES_CBC,
            "type": "symmetric",
            "mode": "CBC",
            "key_size": 64,
            "description": "DES-CBC through OpenSSL for compatibility and comparison.",
        },
        {
            "name": ALGORITHM_RSA_2048,
            "type": "asymmetric",
            "mode": "OAEP-SHA256",
            "key_size": 2048,
            "description": "RSA-2048 demo encryption through OpenSSL for small files or key wrapping.",
        },
        {
            "name": ALGORITHM_DES_LAB,
            "type": "symmetric",
            "mode": "ECB / PKCS7",
            "key_size": 64,
            "description": "DES implementation from laboratory code, educational only.",
        },
        {
            "name": ALGORITHM_RSA_LAB,
            "type": "asymmetric",
            "mode": "Textbook RSA",
            "key_size": 0,
            "description": "Textbook RSA implementation from laboratory code, educational only.",
        },
        {
            "name": "SHA-1-LAB",
            "type": "hash",
            "mode": "SHA-1",
            "key_size": 160,
            "description": "SHA-1 implementation from laboratory code. Educational only.",
        },
        {
            "name": "SHA-256-LAB",
            "type": "hash",
            "mode": "SHA-256",
            "key_size": 256,
            "description": "SHA-256 implementation from laboratory code for file integrity checks.",
        },
        {
            "name": "HMAC-SHA1-LAB",
            "type": "mac",
            "mode": "HMAC-SHA1",
            "key_size": 160,
            "description": "HMAC using SHA-1 from laboratory code.",
        },
        {
            "name": "BASE64-LAB",
            "type": "encoding",
            "mode": "Base64",
            "key_size": 0,
            "description": "Base64 implementation from laboratory code for encoding keys in the database. Encoding, not encryption.",
        },
        {
            "name": "DIGITAL-SIGNATURE-LAB",
            "type": "signature",
            "mode": "SHA-256 + RSA",
            "key_size": 256,
            "description": "Digital signature using SHA-256 + textbook RSA, with minimal PKI simulation.",
        },
    )
    for item in defaults:
        _upsert_named_record(Algorithm, item)

    for stale_name in (ALGORITHM_HYBRID_RSA_AES,):
        stale_algorithm = Algorithm.query.filter_by(name=stale_name).first()
        if stale_algorithm:
            stale_algorithm.description = (
                f"{stale_name} is kept only for backwards compatibility and is not part of the main workflow."
            )

    db.session.commit()


def init_db(seed=True):
    ensure_runtime_directories()
    with app.app_context():
        db.create_all()
        migrate_schema()
        if seed:
            seed_defaults()


init_db(seed=True)
