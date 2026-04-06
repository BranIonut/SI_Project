import subprocess
import time
import os
import binascii


class OpenSSLService:
    @staticmethod
    def encrypt_aes_256_cbc(input_path, output_path, key_bytes):
        key_hex = binascii.hexlify(key_bytes).decode('utf-8')
        iv_hex = "00" * 16

        command = [
            "openssl", "enc", "-aes-256-cbc",
            "-in", input_path,
            "-out", output_path,
            "-K", key_hex,
            "-iv", iv_hex
        ]

        start_time = time.time()

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[Error] OpenSSL: {e.stderr}")
            return -1

        end_time = time.time()

        exec_time_ms = (end_time - start_time) * 1000
        return exec_time_ms