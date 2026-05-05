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
