import hashlib
import secrets

from Business.errors import CryptoServiceError


class CustomPythonService:
    @staticmethod
    def generate_symmetric_key(size_bytes):
        return secrets.token_bytes(size_bytes)

    @staticmethod
    def _xor_bytes(left, right):
        return bytes(a ^ b for a, b in zip(left, right))

    @staticmethod
    def _pkcs7_pad(data, block_size):
        padding_size = block_size - (len(data) % block_size)
        return data + bytes([padding_size]) * padding_size

    @staticmethod
    def _pkcs7_unpad(data, block_size):
        if not data or len(data) % block_size != 0:
            raise CryptoServiceError("Invalid padded data.")
        padding_size = data[-1]
        if padding_size < 1 or padding_size > block_size:
            raise CryptoServiceError("Invalid padding size.")
        if data[-padding_size:] != bytes([padding_size]) * padding_size:
            raise CryptoServiceError("Invalid PKCS7 padding.")
        return data[:-padding_size]

    @staticmethod
    def _feistel_round_function(key_bytes, round_index, data, output_size):
        digest = hashlib.sha256(key_bytes + bytes([round_index]) + data).digest()
        return digest[:output_size]

    @classmethod
    def _encrypt_block(cls, block, key_bytes, rounds):
        half = len(block) // 2
        left = block[:half]
        right = block[half:]
        for round_index in range(rounds):
            function_output = cls._feistel_round_function(key_bytes, round_index, right, half)
            left, right = right, cls._xor_bytes(left, function_output)
        return left + right

    @classmethod
    def _decrypt_block(cls, block, key_bytes, rounds):
        half = len(block) // 2
        left = block[:half]
        right = block[half:]
        for round_index in reversed(range(rounds)):
            function_output = cls._feistel_round_function(key_bytes, round_index, left, half)
            left, right = cls._xor_bytes(right, function_output), left
        return left + right

    @classmethod
    def _encrypt_cbc(cls, input_path, output_path, key_bytes, block_size, rounds):
        iv = secrets.token_bytes(block_size)
        with open(input_path, "rb") as source_file:
            plaintext = source_file.read()
        padded_plaintext = cls._pkcs7_pad(plaintext, block_size)
        previous = iv
        ciphertext_blocks = [iv]
        for index in range(0, len(padded_plaintext), block_size):
            block = padded_plaintext[index:index + block_size]
            xored = cls._xor_bytes(block, previous)
            encrypted = cls._encrypt_block(xored, key_bytes, rounds)
            ciphertext_blocks.append(encrypted)
            previous = encrypted
        with open(output_path, "wb") as target_file:
            target_file.write(b"".join(ciphertext_blocks))

    @classmethod
    def _decrypt_cbc(cls, input_path, output_path, key_bytes, block_size, rounds):
        with open(input_path, "rb") as source_file:
            payload = source_file.read()
        if len(payload) < block_size * 2 or len(payload) % block_size != 0:
            raise CryptoServiceError("Invalid encrypted payload.")
        iv = payload[:block_size]
        ciphertext = payload[block_size:]
        previous = iv
        plaintext_blocks = []
        for index in range(0, len(ciphertext), block_size):
            block = ciphertext[index:index + block_size]
            decrypted = cls._decrypt_block(block, key_bytes, rounds)
            plaintext_blocks.append(cls._xor_bytes(decrypted, previous))
            previous = block
        plaintext = cls._pkcs7_unpad(b"".join(plaintext_blocks), block_size)
        with open(output_path, "wb") as target_file:
            target_file.write(plaintext)

    @classmethod
    def encrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_cbc(input_path, output_path, key_bytes, block_size=16, rounds=8)

    @classmethod
    def decrypt_aes_256_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_cbc(input_path, output_path, key_bytes, block_size=16, rounds=8)

    @classmethod
    def encrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._encrypt_cbc(input_path, output_path, key_bytes, block_size=8, rounds=6)

    @classmethod
    def decrypt_des_cbc(cls, input_path, output_path, key_bytes):
        cls._decrypt_cbc(input_path, output_path, key_bytes, block_size=8, rounds=6)
