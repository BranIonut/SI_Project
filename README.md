# Local Encryption Key Management System

This project is a local encryption key management system for multiple cryptographic algorithms. It manages files, keys, algorithms, frameworks, operation history, and performance data in a local SQLite database, with a PyQt desktop interface for demo use.

## Technologies

- Python
- SQLite via Flask-SQLAlchemy
- OpenSSL CLI invoked through Python `subprocess`
- Python `cryptography` library
- PyQt6
- `pytest` for tests
- `psutil` and `tracemalloc` for performance measurement

## Features

- AES-256-CBC support for normal file encryption/decryption
- RSA-2048 support for small demo files
- OpenSSL integration for AES and RSA
- Alternative AES implementation using `cryptography`
- Local key generation and storage
- Managed file tracking with encrypted/decrypted state
- SHA-256 hashing for original, encrypted, and decrypted files
- Operation history with success/failure tracking
- Performance records for time, memory, input size, and output size
- CRUD support for Framework, Algorithm, Key, ManagedFile, CryptoOperation, and Performance
- Idempotent database seed for default frameworks and algorithms

## Database Entities

### Framework
- `id`
- `name`
- `type`
- `version`
- `created_at`

### Algorithm
- `id`
- `name`
- `type` (`symmetric` or `asymmetric`)
- `mode`
- `key_size`
- `framework_id`
- `description`

### Key
- `id`
- `name`
- `algorithm_id`
- `framework_id`
- `key_type`
- `key_value`
- `key_path`
- `public_key_value`
- `private_key_value`
- `created_at`
- `is_active`

### ManagedFile
- `id`
- `original_name`
- `original_path`
- `encrypted_path`
- `decrypted_path`
- `original_hash`
- `encrypted_hash`
- `decrypted_hash`
- `integrity_verified`
- `status`
- `created_at`
- `updated_at`

### CryptoOperation
- `id`
- `file_id`
- `algorithm_id`
- `framework_id`
- `key_id`
- `operation_type`
- `status`
- `error_message`
- `notes`
- `started_at`
- `finished_at`

### Performance
- `id`
- `operation_id`
- `execution_time_ms`
- `memory_usage_mb`
- `input_size_bytes`
- `output_size_bytes`
- `created_at`

## Default Seed Data

The app seeds these values automatically if they do not already exist:

- Frameworks:
  - `OpenSSL`
  - `Cryptography`
- Algorithms:
  - `AES-256-CBC`
  - `RSA-2048`

The seed is idempotent, so running the app multiple times does not duplicate these rows.

## Crypto Flow

### AES Flow

1. Select a file and register it in the database.
2. Generate or select an AES key.
3. Choose `AES-256-CBC` and a framework (`OpenSSL` or `Cryptography`).
4. Encrypt the file.
5. The application stores:
   - original SHA-256
   - encrypted SHA-256
   - operation history
   - performance data
6. Decrypt the file using the same key.
7. The app compares `original_hash` and `decrypted_hash` and stores the integrity result.

### RSA Flow

1. Generate an RSA key pair.
2. Select a small demo file.
3. Encrypt using the public key with OpenSSL.
4. Decrypt using the private key.
5. The app verifies the decrypted hash against the original file hash.

RSA is intentionally limited to small demo files. For normal file encryption, use AES.

## OpenSSL Integration

OpenSSL is executed from Python using `subprocess.run(...)`. The application looks for:

- `OPENSSL_BIN` environment variable
- `openssl` in `PATH`
- Git for Windows OpenSSL locations:
  - `C:\Program Files\Git\mingw64\bin\openssl.exe`
  - `C:\Program Files\Git\usr\bin\openssl.exe`

Supported OpenSSL operations:

- AES-256-CBC key usage for file encryption/decryption
- RSA-2048 keypair generation
- RSA public-key encryption of small demo files
- RSA private-key decryption

## Alternative Framework Comparison

The alternative framework is Python `cryptography`.

Implemented comparison support:

- AES-256-CBC encryption
- AES-256-CBC decryption
- AES key generation
- optional RSA keypair generation support

Each crypto operation stores the selected framework in the database so OpenSSL and Cryptography performance can be compared later.

## Performance Analysis

Each encryption/decryption operation stores:

- execution time in milliseconds using `time.perf_counter()`
- memory usage in MB using `psutil` and `tracemalloc`
- input size in bytes
- output size in bytes

Performance records are linked to operation history entries.

## Project Structure

- `Model/` - SQLAlchemy models and DB initialization
- `Repositories/` - CRUD access layer
- `Business/` - hashing, key generation, OpenSSL/Cryptography services, operation management
- `Presenter/` - PyQt GUI
- `Tests/` - pytest coverage
- `data/` - original, encrypted, decrypted, and key storage

## How To Run

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Initialize the database and seed defaults:

```bash
python -c "from Model.models import init_db; init_db(seed=True)"
```

Run the desktop app:

```bash
python app.py
```

Run tests:

```bash
python -m pytest -q
```

## Interface Usage

The GUI supports:

- selecting a local file
- registering file metadata in the DB
- selecting an algorithm
- selecting a framework
- selecting an existing key
- generating a new AES key or RSA keypair
- encrypting a file
- decrypting a file
- viewing file status and hashes
- viewing recent operations and performance data
- displaying stored keys in debug/admin mode

## Data Folders

- `data/original/`
- `data/encrypted/`
- `data/decrypted/`
- `data/keys/`

## Limitations

- RSA is only used for small demo files or direct content encryption.
- AES should be used for normal file encryption.
- Keys are stored locally for academic/demo purposes.
- This is a local desktop project and does not include user authentication or remote key vault features.
