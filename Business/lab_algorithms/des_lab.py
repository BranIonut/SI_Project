from typing import List, Tuple

BitList = List[str]

IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
]

IP_1 = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
]

E_TABLE = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29,
    30, 31, 32, 1
]

PC_1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
]

PC_2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
]

ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def permute(block: BitList, table: List[int]) -> BitList:
    return [block[pos - 1] for pos in table]


def split(block: BitList) -> Tuple[BitList, BitList]:
    mid_point = len(block) // 2
    return block[:mid_point], block[mid_point:]


def left_rotate(C: BitList, D: BitList, round_index: int) -> Tuple[BitList, BitList]:
    shift = ROTATIONS[round_index]
    return C[shift:] + C[:shift], D[shift:] + D[:shift]


def generate_subkeys(key: BitList) -> List[BitList]:
    key = permute(key, PC_1)
    C, D = split(key)

    subkeys = []
    for i in range(16):
        C, D = left_rotate(C, D, i)
        subkeys.append(permute(C + D, PC_2))

    return subkeys


def xor_bits(bits1: BitList, bits2: BitList) -> BitList:
    return [str(int(a) ^ int(b)) for a, b in zip(bits1, bits2)]


def feistel(R: BitList, K: BitList) -> BitList:
    expanded_R = permute(R, E_TABLE)
    xored = xor_bits(expanded_R, K)

    s_output = []
    for i in range(8):
        chunk = xored[i * 6:(i + 1) * 6]

        row = int(chunk[0] + chunk[5], 2)
        col = int("".join(chunk[1:5]), 2)

        s_val = S_BOXES[i][row][col]
        s_output.extend(list(f"{s_val:04b}"))

    return permute(s_output, P)


def encrypt_block(block: BitList, subkeys: List[BitList]) -> BitList:
    if len(block) != 64:
        raise ValueError("DES block must have exactly 64 bits.")

    block = permute(block, IP)
    L, R = split(block)

    for i in range(16):
        next_L = R
        f_result = feistel(R, subkeys[i])
        next_R = xor_bits(L, f_result)
        L, R = next_L, next_R

    return permute(R + L, IP_1)


def decrypt_block(block: BitList, subkeys: List[BitList]) -> BitList:
    return encrypt_block(block, subkeys[::-1])


def bytes_to_bits(data: bytes) -> BitList:
    return list("".join(f"{byte:08b}" for byte in data))


def bits_to_bytes(bit_list: BitList) -> bytes:
    bit_string = "".join(bit_list)
    return bytes(int(bit_string[i:i + 8], 2) for i in range(0, len(bit_string), 8))


def pkcs7_pad(data: bytes, block_size: int = 8) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")

    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid PKCS#7 padding.")

    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Invalid PKCS#7 padding bytes.")

    return data[:-padding_len]


def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    key = key.ljust(8, b" ")[:8]
    subkeys = generate_subkeys(bytes_to_bits(key))

    padded_data = pkcs7_pad(data, 8)
    encrypted = bytearray()

    for i in range(0, len(padded_data), 8):
        block_bits = bytes_to_bits(padded_data[i:i + 8])
        encrypted_bits = encrypt_block(block_bits, subkeys)
        encrypted.extend(bits_to_bytes(encrypted_bits))

    return bytes(encrypted)


def decrypt_bytes(ciphertext: bytes, key: bytes) -> bytes:
    key = key.ljust(8, b" ")[:8]
    subkeys = generate_subkeys(bytes_to_bits(key))

    if len(ciphertext) % 8 != 0:
        raise ValueError("DES ciphertext length must be multiple of 8 bytes.")

    decrypted = bytearray()

    for i in range(0, len(ciphertext), 8):
        block_bits = bytes_to_bits(ciphertext[i:i + 8])
        decrypted_bits = decrypt_block(block_bits, subkeys)
        decrypted.extend(bits_to_bytes(decrypted_bits))

    return pkcs7_unpad(bytes(decrypted), 8)


def encrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    with open(input_path, "rb") as f:
        data = f.read()

    encrypted = encrypt_bytes(data, key)

    with open(output_path, "wb") as f:
        f.write(encrypted)


def decrypt_file(input_path: str, output_path: str, key: bytes) -> None:
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    decrypted = decrypt_bytes(ciphertext, key)

    with open(output_path, "wb") as f:
        f.write(decrypted)
