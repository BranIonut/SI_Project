# Local Encryption Key Management System

## Purpose

This project is a local key-management and file encryption/decryption system with:

- a PyQt6 desktop UI
- SQLite persistence through Flask-SQLAlchemy
- managed files, algorithms, frameworks, keys, operations, and performance records
- OpenSSL subprocess integration
- a real Python cryptography framework for comparison
- an educational laboratory framework for comparison

The main workflow is:

1. register a file
2. choose algorithm and framework
3. generate or select a compatible key
4. encrypt or decrypt
5. review hashes, operation history, and performance metrics

## Main Frameworks

### 1. OpenSSL

Mandatory framework required by the project statement.

Main algorithms:

- `AES-256-CBC`
- `DES-CBC`
- `RSA-2048`

### 2. Python cryptography

Real Python cryptography framework used as an alternative to OpenSSL for encryption/decryption and performance comparison.

Main algorithms:

- `AES-256-CBC`
- `AES-256-GCM`
- `RSA-2048`

### 3. Lab Educational

Educational framework based on laboratory implementations. It is used for comparison and learning, not production use.

Main algorithms:

- `DES-LAB`
- `RSA-LAB`

### Legacy compatibility

- `Custom Educational / Legacy`

This legacy framework is compatibility-only. It may appear when working with older databases, but it is not seeded as an active framework for the main workflow.

## Main Workflow Algorithms

### OpenSSL

- `AES-256-CBC`: symmetric file encryption/decryption
- `DES-CBC`: OpenSSL DES path kept for comparison
- `RSA-2048`: asymmetric encryption/decryption for small demo files

### Python cryptography

- `AES-256-CBC`: symmetric file encryption/decryption
- `AES-256-GCM`: authenticated symmetric encryption/decryption
- `RSA-2048`: asymmetric encryption/decryption for small demo files

### Lab Educational

- `DES-LAB`: educational DES file encryption/decryption
- `RSA-LAB`: educational textbook RSA file encryption/decryption

## Internal Support

The project also keeps and uses educational support modules internally:

- `SHA-256-LAB` for file hash and integrity calculation
- `BASE64-LAB` for symmetric key encoding in storage

Additional educational modules may remain in the codebase for tests or completeness, but they are not part of the main encrypt/decrypt workflow.

## Not Part Of The Main Workflow

These modules remain in the codebase for completeness, but they are not exposed as primary workflow actions:

- `SHA-1-LAB`
- `BASE64-LAB` as a standalone encode/decode feature
- `HMAC-SHA1-LAB`
- `DIGITAL-SIGNATURE-LAB`
- standalone modular arithmetic demos
- `Hybrid RSA-AES` as a future extension / legacy path unless it is explicitly routed and tested

Important:

- Base64 is encoding, not encryption.
- HMAC and digital signatures are not part of the main file encrypt/decrypt workflow.
- Lab Educational algorithms are educational and not production-grade.
- OpenSSL remains the mandatory framework required by the project scope.
- Python cryptography is the real alternative framework used for performance comparison.

## Data And Persistence

The application manages:

- files
- algorithms
- frameworks
- keys
- crypto operations
- performance records

For every successful encryption/decryption operation, the system stores:

- output file paths
- SHA-256 hashes
- integrity verification state
- operation history
- execution time
- memory usage
- normalized throughput metrics

## Performance Tracking

Every successful operation stores:

- `execution_time_ms`
- `memory_usage_mb`
- `input_size_bytes`
- `output_size_bytes`
- `time_per_byte_ms`
- `time_per_byte_us`
- `throughput_bytes_per_second`
- `throughput_mib_per_second`

This supports comparison between:

- OpenSSL
- Python cryptography
- Lab Educational

## Run The App

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Initialize or refresh the local database:

```bash
python -c "from Model.models import init_db; init_db(seed=True)"
```

Run the application:

```bash
python app.py
```

## Validation

Run tests:

```bash
python -m pytest -q
```

Run compile validation:

```bash
python -m compileall .
```

## Security Notes

- OpenSSL is the main required framework.
- Keys are stored locally for academic/demo purposes.
- `DES-LAB` and `RSA-LAB` are educational implementations only.
- `RSA-2048` direct file encryption is limited to small demo payloads.
- OpenSSL support depends on a working executable available in `PATH` or through `OPENSSL_BIN`.
