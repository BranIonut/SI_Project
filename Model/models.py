import os
from datetime import datetime, timezone

from flask import Flask
from flask_sqlalchemy import SQLAlchemy


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
    type = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50))
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
    updated_at = db.Column(
        db.DateTime, nullable=False, default=utc_now, onupdate=utc_now
    )


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


def seed_defaults():
    open_ssl = Framework.query.filter_by(name="OpenSSL").first()
    if not open_ssl:
        open_ssl = Framework(name="OpenSSL", type="CLI / subprocess", version=None)
        db.session.add(open_ssl)

    cryptography_fw = Framework.query.filter_by(name="Cryptography").first()
    if not cryptography_fw:
        cryptography_fw = Framework(
            name="Cryptography",
            type="Python library",
            version=None,
        )
        db.session.add(cryptography_fw)

    db.session.flush()

    defaults = (
        {
            "name": "AES-256-CBC",
            "type": "symmetric",
            "mode": "CBC",
            "key_size": 256,
            "description": "AES file encryption for normal local files.",
        },
        {
            "name": "RSA-2048",
            "type": "asymmetric",
            "mode": None,
            "key_size": 2048,
            "description": "RSA demo encryption for small files or content.",
        },
    )
    for item in defaults:
        if not Algorithm.query.filter_by(name=item["name"]).first():
            db.session.add(Algorithm(**item))

    db.session.commit()


def init_db(seed=True):
    ensure_runtime_directories()
    with app.app_context():
        db.create_all()
        if seed:
            seed_defaults()


init_db(seed=True)
