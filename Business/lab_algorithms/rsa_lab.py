from dataclasses import dataclass
from pathlib import Path


def power_modular(base: int, exponent: int, mod: int) -> int:
    if mod <= 0:
        raise ValueError("mod must be positive.")

    if mod == 1:
        return 0

    if exponent < 0:
        raise ValueError("exponent must be non-negative.")

    result = 1
    base = base % mod

    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % mod

        base = (base * base) % mod
        exponent //= 2

    return result


@dataclass
class RSAKeyPair:
    p: int
    q: int
    n: int
    phi: int
    e: int
    d: int


def generate_demo_key_pair(p: int = 61, q: int = 53, e: int = 17) -> RSAKeyPair:
    if p == q:
        raise ValueError("p and q must be different primes.")

    n = p * q
    phi = (p - 1) * (q - 1)

    try:
        d = pow(e, -1, phi)
    except ValueError as exc:
        raise ValueError("e does not have modular inverse modulo phi.") from exc

    return RSAKeyPair(p=p, q=q, n=n, phi=phi, e=e, d=d)


def rsa_encrypt_number(message_number: int, e: int, n: int) -> int:
    if not 0 <= message_number < n:
        raise ValueError("message_number must satisfy 0 <= message_number < n.")

    return power_modular(message_number, e, n)


def rsa_decrypt_number(cipher_number: int, d: int, n: int) -> int:
    if not 0 <= cipher_number < n:
        raise ValueError("cipher_number must satisfy 0 <= cipher_number < n.")

    return power_modular(cipher_number, d, n)


def rsa_encrypt_bytes(data: bytes, e: int, n: int) -> list[int]:
    if n <= 255:
        raise ValueError("n must be greater than 255 for byte-by-byte encryption.")

    encrypted_values = []
    for byte in data:
        encrypted_values.append(rsa_encrypt_number(byte, e, n))

    return encrypted_values


def rsa_decrypt_bytes(encrypted_values: list[int], d: int, n: int) -> bytes:
    decrypted = bytearray()

    for value in encrypted_values:
        m = rsa_decrypt_number(value, d, n)

        if not 0 <= m <= 255:
            raise ValueError("Decrypted value does not fit in one byte.")

        decrypted.append(m)

    return bytes(decrypted)


def rsa_encrypt_file(input_filename: str, output_filename: str, e: int, n: int) -> None:
    input_path = Path(input_filename)
    output_path = Path(output_filename)

    with input_path.open("rb") as f_in:
        data = f_in.read()

    encrypted_values = rsa_encrypt_bytes(data, e, n)

    with output_path.open("w", encoding="utf-8") as f_out:
        for value in encrypted_values:
            f_out.write(f"{value}\n")


def rsa_decrypt_file(input_filename: str, output_filename: str, d: int, n: int) -> None:
    input_path = Path(input_filename)
    output_path = Path(output_filename)

    encrypted_values = []
    with input_path.open("r", encoding="utf-8") as f_in:
        for line in f_in:
            line = line.strip()
            if line:
                encrypted_values.append(int(line))

    decrypted = rsa_decrypt_bytes(encrypted_values, d, n)

    with output_path.open("wb") as f_out:
        f_out.write(decrypted)
