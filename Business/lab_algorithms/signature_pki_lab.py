# signature_pki_lab.py
# Educational digital signature and minimal PKI simulation.
# Uses SHA-256 + textbook RSA from the lab.

import time
from dataclasses import dataclass


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


def right_rotate(n: int, b: int, bits: int) -> int:
    return ((n >> b) | (n << (bits - b))) & ((1 << bits) - 1)


def sha256_padding(message: bytes) -> bytes:
    original_length_bits = len(message) * 8
    zeros_needed = (55 - len(message)) % 64
    length_bytes = original_length_bits.to_bytes(8, byteorder="big")
    return message + b"\x80" + (b"\x00" * zeros_needed) + length_bytes


def sha256(message_bytes: bytes) -> str:
    h = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    K = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ]

    message = sha256_padding(bytes(message_bytes))

    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]
        w = [int.from_bytes(chunk[j * 4:j * 4 + 4], byteorder="big") for j in range(16)] + [0] * 48

        for j in range(16, 64):
            s0 = right_rotate(w[j - 15], 7, 32) ^ right_rotate(w[j - 15], 18, 32) ^ (w[j - 15] >> 3)
            s1 = right_rotate(w[j - 2], 17, 32) ^ right_rotate(w[j - 2], 19, 32) ^ (w[j - 2] >> 10)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f_val, g, h_val = h

        for j in range(64):
            S1 = right_rotate(e, 6, 32) ^ right_rotate(e, 11, 32) ^ right_rotate(e, 25, 32)
            ch = (e & f_val) ^ (~e & g)
            temp1 = (h_val + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF

            S0 = right_rotate(a, 2, 32) ^ right_rotate(a, 13, 32) ^ right_rotate(a, 22, 32)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h_val = g
            g = f_val
            f_val = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f_val) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_val) & 0xFFFFFFFF

    return "".join(f"{val:08x}" for val in h)


@dataclass
class Certificate:
    owner: str
    issuer: str
    public_key: tuple[int, int]
    valid_from: float
    valid_to: float
    algorithms: str


class CertificateAuthority:
    def __init__(self, name: str):
        self.name = name

    def issue_certificate(self, owner_name: str, public_key: tuple[int, int]) -> Certificate:
        current_time = time.time()

        return Certificate(
            owner=owner_name,
            issuer=self.name,
            public_key=public_key,
            valid_from=current_time,
            valid_to=current_time + 31_536_000,
            algorithms="SHA256 + RSA",
        )


@dataclass
class SignedDocument:
    m: str
    s: int
    hash_algo: str
    timestamp: float


class PKISystem:
    def __init__(self, n: int, e: int, d: int):
        self.n = n
        self.e = e
        self.d = d

    def create_signed_doc(self, message: str) -> SignedDocument:
        hash_hex = sha256(message.encode("utf-8"))
        hash_val = int(hash_hex, 16) % self.n

        signature = power_modular(hash_val, self.d, self.n)

        return SignedDocument(
            m=message,
            s=signature,
            hash_algo="SHA256",
            timestamp=time.time(),
        )

    def verify_with_cert(self, signed_doc: SignedDocument, cert: Certificate) -> bool:
        current_time = time.time()

        if not (cert.valid_from <= current_time <= cert.valid_to):
            return False

        n_pub, e_pub = cert.public_key

        current_hash_hex = sha256(signed_doc.m.encode("utf-8"))
        current_hash = int(current_hash_hex, 16) % n_pub

        decrypted_hash = power_modular(signed_doc.s, e_pub, n_pub)

        return current_hash == decrypted_hash


def demo() -> None:
    n, e, d = 3233, 17, 413

    ca = CertificateAuthority("GlobalRootCA")
    user_cert = ca.issue_certificate("User1", (n, e))

    pki = PKISystem(n, e, d)
    doc = pki.create_signed_doc("Confidential Data")

    result = pki.verify_with_cert(doc, user_cert)

    print(f"Verification using CA certificate: {result}")
    print(f"Document signed at timestamp: {doc.timestamp}")


if __name__ == "__main__":
    demo()
