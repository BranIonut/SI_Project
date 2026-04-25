# Local Encryption Key Management System

This project is a local encryption key management system built on the existing project structure. It manages files, keys, algorithms, frameworks, hashes, and performance data in a local SQLite database through a PyQt desktop interface.

## Frameworks

The project supports exactly two frameworks:

- OpenSSL
- Custom Python implementation

## Algorithms

- AES-256-CBC
- DES-CBC
- RSA-2048
- SHA-256 for file integrity

## What The App Does

- register files in the local database
- generate AES, DES, and RSA keys
- encrypt and decrypt files
- store original, encrypted, and decrypted file paths
- compute and store SHA-256 hashes
- verify `original_hash == decrypted_hash`
- store operation history and performance metrics

## Database Entities

- `Framework`
- `Algorithm`
- `Key`
- `ManagedFile`
- `CryptoOperation`
- `Performance`

## OpenSSL Support

OpenSSL is used through `subprocess` for:

- AES-256-CBC encrypt/decrypt
- DES-CBC encrypt/decrypt
- RSA-2048 key generation
- RSA-2048 encrypt/decrypt for small files

## Custom Python Support

The second framework is implemented in project code and is used for:

- AES-256-CBC educational CBC implementation
- DES-CBC educational CBC implementation
- SHA-256 hashing with `hashlib`

This framework exists for comparison with OpenSSL and keeps the project simple and explainable for presentation.

## File Flow

For encryption:

1. compute SHA-256 of original file
2. encrypt file
3. compute SHA-256 of encrypted file
4. store file paths, hashes, operation, and performance in DB

For decryption:

1. decrypt file
2. compute SHA-256 of decrypted file
3. compare decrypted hash with original hash
4. update file status and store operation/performance

## Run

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Initialize database:

```bash
python -c "from Model.models import init_db; init_db(seed=True)"
```

Run application:

```bash
python app.py
```

Run tests:

```bash
python -m pytest -q
```

## Notes

- RSA is only for small demo files
- AES and DES are used for symmetric file encryption tests
- keys are stored locally for academic/demo purposes
