# base64_lab.py
# Base64 educational implementation based on the laboratory code.
# Base64 is encoding, not encryption.

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def to_binary(data: bytes) -> str:
    return "".join(format(byte, "08b") for byte in data)


def encode_base64_bytes(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("encode_base64_bytes expects bytes.")

    bit_string = to_binary(bytes(data))

    padding_bits = (6 - len(bit_string) % 6) % 6
    bit_string += "0" * padding_bits

    encoded = ""
    for i in range(0, len(bit_string), 6):
        segment = bit_string[i:i + 6]
        index = int(segment, 2)
        encoded += BASE64_ALPHABET[index]

    while len(encoded) % 4:
        encoded += "="

    return encoded


def decode_base64_bytes(encoded_text: str) -> bytes:
    if not isinstance(encoded_text, str):
        raise TypeError("decode_base64_bytes expects string.")

    clean_text = encoded_text.strip().rstrip("=")

    bit_string = ""
    for char in clean_text:
        if char not in BASE64_ALPHABET:
            raise ValueError(f"Invalid Base64 character: {char}")

        index = BASE64_ALPHABET.index(char)
        bit_string += format(index, "06b")

    decoded = bytearray()
    for i in range(0, len(bit_string), 8):
        segment = bit_string[i:i + 8]
        if len(segment) == 8:
            decoded.append(int(segment, 2))

    return bytes(decoded)


def encode_base64(text: str) -> str:
    return encode_base64_bytes(text.encode("utf-8"))


def decode_base64(encoded_text: str) -> str:
    return decode_base64_bytes(encoded_text).decode("utf-8", errors="replace")


def encode_file_to_base64(input_path: str, output_path: str) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    encoded = encode_base64_bytes(data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(encoded)


def decode_file_from_base64(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as f:
        encoded = f.read()

    decoded = decode_base64_bytes(encoded)

    with open(output_path, "wb") as f:
        f.write(decoded)


def demo() -> None:
    text = input("Input: ")
    encoded = encode_base64(text)
    print("base64 encoded:", encoded)

    decoded = decode_base64(encoded)
    print("decoded text:", decoded)


if __name__ == "__main__":
    demo()
