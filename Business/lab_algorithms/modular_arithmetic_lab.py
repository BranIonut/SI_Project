# modular_arithmetic_lab.py
# Efficient modular exponentiation used by RSA.

def power_modular(base: int, exponent: int, mod: int) -> int:
    """
    Computes (base ** exponent) % mod using square-and-multiply.
    This keeps the same logic from the lab, with small validation added.
    """
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


def demo() -> None:
    print(power_modular(289, 11, 1363))


if __name__ == "__main__":
    demo()
